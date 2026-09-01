using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using Detector.Heuristics;
using Detector.Model;

namespace Detector.Analysis;

internal static class PeArtifactAnalyzer
{
    public static PeAnalysis Analyze(string path, ArtifactProfile fingerprint, AnalysisLimits limits)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
        var headers = pe.PEHeaders;
        var peHeader = headers.PEHeader ?? throw new BadImageFormatException("The file has no PE optional header.");
        var sections = headers.SectionHeaders.Take(limits.MaximumPeSections)
            .Select(section => ReadSection(pe, section))
            .ToArray();
        var nativeImports = ReadNativeImports(pe, limits.MaximumMetadataItems);
        var nativeApiReferences = new List<ApiReference>();
        foreach (var import in nativeImports)
        {
            var separator = import.IndexOf('!');
            if (separator > 0)
                AddApi(nativeApiReferences, import[..separator], import[(separator + 1)..], "native import");
        }

        var profile = fingerprint with
        {
            Kind = pe.HasMetadata ? ArtifactKind.ManagedAssembly : ArtifactKind.PortableExecutable,
            Architecture = headers.CoffHeader.Machine.ToString(),
            Subsystem = peHeader.Subsystem.ToString(),
            PeTimestamp = ReadTimestamp(headers.CoffHeader.TimeDateStamp),
            Sections = sections,
            NativeImports = nativeImports,
            ApiReferences = nativeApiReferences
        };
        var findings = new List<Detection>();
        if (!pe.HasMetadata)
        {
            AddApiFindings(findings, nativeApiReferences, path);
            return new PeAnalysis(profile, findings);
        }

        var reader = pe.GetMetadataReader(MetadataReaderOptions.ApplyWindowsRuntimeProjections);
        var references = reader.AssemblyReferences
            .Take(limits.MaximumMetadataItems)
            .Select(handle => reader.GetString(reader.GetAssemblyReference(handle).Name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var types = reader.TypeDefinitions
            .Take(limits.MaximumMetadataItems)
            .Select(handle => TypeName(reader, handle))
            .Where(value => value.Length > 0)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var methods = reader.MethodDefinitions
            .Take(limits.MaximumMetadataItems)
            .Select(handle => reader.GetString(reader.GetMethodDefinition(handle).Name))
            .Where(value => value.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var apiReferences = ReadApiReferences(reader, limits.MaximumMetadataItems)
            .Concat(nativeApiReferences).Distinct()
            .OrderBy(item => item.Family, StringComparer.Ordinal)
            .ThenBy(item => item.Member, StringComparer.Ordinal)
            .Take(limits.MaximumMetadataItems).ToArray();
        var assembly = reader.IsAssembly ? reader.GetAssemblyDefinition() : default;
        var assemblyName = reader.IsAssembly ? reader.GetString(assembly.Name) : null;
        var assemblyVersion = reader.IsAssembly ? assembly.Version.ToString() : null;

        profile = profile with
        {
            AssemblyName = assemblyName,
            AssemblyVersion = assemblyVersion,
            TargetFramework = ReadTargetFramework(reader),
            EntryPoint = ReadEntryPoint(pe, reader),
            AssemblyReferences = references,
            DeclaredTypes = types,
            DeclaredMethods = methods,
            ApiReferences = apiReferences
        };

        AddApiFindings(findings, apiReferences, path);
        return new PeAnalysis(profile, findings);
    }

    private static void AddApiFindings(List<Detection> findings, IEnumerable<ApiReference> apiReferences, string path)
    {
        foreach (var group in apiReferences.GroupBy(item => item.Family, StringComparer.Ordinal))
        {
            var members = string.Join(", ", group.Select(item => item.Member).Distinct(StringComparer.Ordinal).Take(8));
            findings.Add(new Detection(
                "PE/.NET metadata",
                path,
                Severity.Low,
                Verdict.Suspicious,
                $"metadata.api.{group.Key}",
                $"Metadata references {group.Key} API(s): {members}")
            { Path = path });
        }
    }

    private static string[] ReadNativeImports(PEReader pe, int maximum)
    {
        var directory = pe.PEHeaders.PEHeader!.ImportTableDirectory;
        if (directory.RelativeVirtualAddress == 0 || maximum <= 0) return [];
        var descriptors = pe.GetSectionData(directory.RelativeVirtualAddress).GetContent().AsSpan();
        var descriptorBytes = directory.Size > 0 ? Math.Min(descriptors.Length, directory.Size) : descriptors.Length;
        var imports = new List<string>();
        for (var offset = 0; offset <= descriptorBytes - 20 && imports.Count < maximum; offset += 20)
        {
            var descriptor = descriptors.Slice(offset, 20);
            var originalThunk = BinaryPrimitives.ReadUInt32LittleEndian(descriptor);
            var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.Slice(12, 4));
            var firstThunk = BinaryPrimitives.ReadUInt32LittleEndian(descriptor.Slice(16, 4));
            if (originalThunk == 0 && nameRva == 0 && firstThunk == 0) break;
            var module = ReadAscii(pe, nameRva, 260);
            if (module is null) continue;
            var thunkRva = originalThunk != 0 ? originalThunk : firstThunk;
            ReadThunkTable(pe, thunkRva, module, maximum, imports);
        }
        return imports.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static void ReadThunkTable(PEReader pe, uint thunkRva, string module, int maximum, List<string> imports)
    {
        var is64 = pe.PEHeaders.PEHeader!.Magic == PEMagic.PE32Plus;
        var width = is64 ? 8 : 4;
        var ordinalMask = is64 ? 0x8000000000000000UL : 0x80000000UL;
        for (var index = 0; index < maximum && imports.Count < maximum; index++)
        {
            var rva = checked((int)(thunkRva + (uint)(index * width)));
            var content = pe.GetSectionData(rva).GetContent(0, width).AsSpan();
            var value = is64
                ? BinaryPrimitives.ReadUInt64LittleEndian(content)
                : BinaryPrimitives.ReadUInt32LittleEndian(content);
            if (value == 0) break;
            if ((value & ordinalMask) != 0)
            {
                imports.Add($"{module}!#{value & 0xffff}");
                continue;
            }
            var name = ReadAscii(pe, checked((uint)value + 2), 512);
            if (name is not null) imports.Add($"{module}!{name}");
        }
    }

    private static string? ReadAscii(PEReader pe, uint rva, int maximumLength)
    {
        if (rva > int.MaxValue) return null;
        var content = pe.GetSectionData((int)rva).GetContent().AsSpan();
        var length = 0;
        while (length < content.Length && length < maximumLength && content[length] != 0)
        {
            if (content[length] is < 0x20 or > 0x7e) return null;
            length++;
        }
        if (length == 0 || length == maximumLength || length == content.Length) return null;
        return System.Text.Encoding.ASCII.GetString(content[..length]);
    }

    private static PeSectionProfile ReadSection(PEReader pe, SectionHeader section)
    {
        var available = pe.GetSectionData(section.VirtualAddress);
        var length = Math.Min(Math.Max(section.SizeOfRawData, 0), available.Length);
        var bytes = length == 0 ? ReadOnlySpan<byte>.Empty : available.GetContent(0, length).AsSpan();
        return new PeSectionProfile(
            section.Name,
            section.VirtualSize,
            section.SizeOfRawData,
            ContentHeuristics.ShannonEntropy(bytes),
            section.SectionCharacteristics.ToString());
    }

    private static DateTimeOffset? ReadTimestamp(int seconds)
    {
        try { return DateTimeOffset.FromUnixTimeSeconds(unchecked((uint)seconds)); }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    private static string? ReadTargetFramework(MetadataReader reader)
    {
        foreach (var handle in reader.CustomAttributes)
        {
            var attribute = reader.GetCustomAttribute(handle);
            if (!string.Equals(AttributeTypeName(reader, attribute.Constructor),
                    "System.Runtime.Versioning.TargetFrameworkAttribute", StringComparison.Ordinal))
                continue;
            try
            {
                var value = reader.GetBlobReader(attribute.Value);
                if (value.ReadUInt16() != 1) return null;
                return value.ReadSerializedString();
            }
            catch (BadImageFormatException) { return null; }
        }
        return null;
    }

    private static string? AttributeTypeName(MetadataReader reader, EntityHandle constructor)
    {
        EntityHandle type = constructor.Kind switch
        {
            HandleKind.MemberReference => reader.GetMemberReference((MemberReferenceHandle)constructor).Parent,
            HandleKind.MethodDefinition => reader.GetMethodDefinition((MethodDefinitionHandle)constructor).GetDeclaringType(),
            _ => default
        };
        return type.Kind switch
        {
            HandleKind.TypeReference => TypeName(reader, (TypeReferenceHandle)type),
            HandleKind.TypeDefinition => TypeName(reader, (TypeDefinitionHandle)type),
            _ => null
        };
    }

    private static string? ReadEntryPoint(PEReader pe, MetadataReader reader)
    {
        var cor = pe.PEHeaders.CorHeader;
        if (cor is null || (cor.Flags & CorFlags.NativeEntryPoint) != 0 || cor.EntryPointTokenOrRelativeVirtualAddress == 0)
            return null;
        try
        {
            var handle = MetadataTokens.Handle(cor.EntryPointTokenOrRelativeVirtualAddress);
            if (handle.Kind != HandleKind.MethodDefinition) return null;
            var method = reader.GetMethodDefinition((MethodDefinitionHandle)handle);
            return $"{TypeName(reader, method.GetDeclaringType())}.{reader.GetString(method.Name)}";
        }
        catch (BadImageFormatException) { return null; }
    }

    private static ApiReference[] ReadApiReferences(MetadataReader reader, int maximum)
    {
        var result = new List<ApiReference>();
        foreach (var handle in reader.MemberReferences.Take(maximum))
        {
            var member = reader.GetMemberReference(handle);
            var name = reader.GetString(member.Name);
            var owner = MemberOwnerName(reader, member.Parent);
            AddApi(result, owner, name, "member reference");
        }
        foreach (var handle in reader.MethodDefinitions.Take(maximum))
        {
            var method = reader.GetMethodDefinition(handle);
            if ((method.Attributes & MethodAttributes.PinvokeImpl) == 0) continue;
            var import = method.GetImport();
            var module = reader.GetString(reader.GetModuleReference(import.Module).Name);
            var name = reader.GetString(import.Name);
            AddApi(result, module, name, "P/Invoke");
            result.Add(new ApiReference("pinvoke", name, module));
        }
        return result.Distinct().OrderBy(item => item.Family, StringComparer.Ordinal)
            .ThenBy(item => item.Member, StringComparer.Ordinal).Take(maximum).ToArray();
    }

    private static void AddApi(List<ApiReference> result, string owner, string member, string evidence)
    {
        var family = ApiFamily(owner, member);
        if (family is not null) result.Add(new ApiReference(family, member, $"{owner} ({evidence})"));
    }

    private static string? ApiFamily(string owner, string member)
    {
        var value = $"{owner}.{member}";
        if (ContainsAny(value, "OpenProcess", "NtOpenProcess", "GetProcessById")) return "process-access";
        if (ContainsAny(value, "VirtualAllocEx", "NtAllocateVirtualMemory")) return "memory-allocation";
        if (ContainsAny(value, "WriteProcessMemory", "NtWriteVirtualMemory")) return "memory-write";
        if (ContainsAny(value, "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC")) return "remote-execution";
        if (ContainsAny(value, "Assembly.Load", "Assembly.LoadFrom", "NativeLibrary.Load", "LoadLibrary")) return "dynamic-loading";
        if (ContainsAny(value, "HttpClient", "WebClient", "WinHttp", "InternetOpen")) return "network";
        if (ContainsAny(value, "RegistryKey.SetValue", "CreateService", "TaskService")) return "persistence";
        if (ContainsAny(value, "CredRead", "LsaRetrievePrivateData", "CryptUnprotectData")) return "credential-access";
        return null;
    }

    private static bool ContainsAny(string value, params string[] tokens) =>
        tokens.Any(token => value.Contains(token, StringComparison.OrdinalIgnoreCase));

    private static string MemberOwnerName(MetadataReader reader, EntityHandle owner) => owner.Kind switch
    {
        HandleKind.TypeReference => TypeName(reader, (TypeReferenceHandle)owner),
        HandleKind.TypeDefinition => TypeName(reader, (TypeDefinitionHandle)owner),
        HandleKind.ModuleReference => reader.GetString(reader.GetModuleReference((ModuleReferenceHandle)owner).Name),
        _ => owner.Kind.ToString()
    };

    private static string TypeName(MetadataReader reader, TypeDefinitionHandle handle)
    {
        var type = reader.GetTypeDefinition(handle);
        return JoinTypeName(reader.GetString(type.Namespace), reader.GetString(type.Name));
    }

    private static string TypeName(MetadataReader reader, TypeReferenceHandle handle)
    {
        var type = reader.GetTypeReference(handle);
        return JoinTypeName(reader.GetString(type.Namespace), reader.GetString(type.Name));
    }

    private static string JoinTypeName(string ns, string name) =>
        string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
}

internal sealed record PeAnalysis(ArtifactProfile Artifact, IReadOnlyList<Detection> Findings);
