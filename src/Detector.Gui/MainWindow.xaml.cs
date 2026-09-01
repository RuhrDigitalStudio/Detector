using System.IO;
using System.Windows;
using Microsoft.Win32;

namespace Detector.Gui;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _viewModel;
        Closed += (_, _) => _viewModel.Cleanup();
    }

    private async void AnalyzeFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose an artifact to inspect",
            Filter = "Analyzable files|*.exe;*.dll;*.ps1;*.psm1;*.cs;*.csx;*.bat;*.cmd;*.js;*.vbs;*.txt|All files|*.*"
        };
        if (dialog.ShowDialog(this) == true) await _viewModel.AnalyzePathAsync(dialog.FileName);
    }

    private async void AnalyzeFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose a folder to inspect", Multiselect = false };
        if (dialog.ShowDialog(this) == true) await _viewModel.AnalyzePathAsync(dialog.FolderName);
    }

    private async void ImportTrace_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Import normalized or Sysmon JSONL evidence",
            Filter = "JSON Lines|*.jsonl;*.ndjson|All files|*.*"
        };
        if (dialog.ShowDialog(this) == true) await _viewModel.ImportRuntimeTraceAsync(dialog.FileName);
    }

    private void ExportJson_Click(object sender, RoutedEventArgs e) => Export(CaseExportFormat.Json);

    private void ExportHtml_Click(object sender, RoutedEventArgs e) => Export(CaseExportFormat.Html);

    private void Export(CaseExportFormat format)
    {
        var extension = format == CaseExportFormat.Json ? ".json" : ".html";
        var dialog = new SaveFileDialog
        {
            Title = $"Export Detector {format} report",
            Filter = format == CaseExportFormat.Json ? "JSON report|*.json" : "HTML report|*.html",
            DefaultExt = extension,
            FileName = $"detector-report{extension}",
            OverwritePrompt = true
        };
        if (dialog.ShowDialog(this) != true) return;
        try { _viewModel.ExportCurrentCase(dialog.FileName, format, overwrite: File.Exists(dialog.FileName)); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private async void Window_Drop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop) ||
            e.Data.GetData(DataFormats.FileDrop) is not string[] paths || paths.Length == 0) return;
        if (paths[0].EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase) ||
            paths[0].EndsWith(".ndjson", StringComparison.OrdinalIgnoreCase))
            await _viewModel.ImportRuntimeTraceAsync(paths[0]);
        else
            await _viewModel.AnalyzePathAsync(paths[0]);
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }
}
