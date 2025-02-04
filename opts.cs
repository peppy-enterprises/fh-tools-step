using System;
using System.CommandLine;
using System.CommandLine.Binding;
using System.IO;

namespace Fahrenheit.Tools.STEP;

internal static class FhSTEPConfig {
    public static string SrcPath  = string.Empty;
    public static string DestPath = string.Empty;

    public static void CLIRead(FhSTEPArgs args) {
        SrcPath  = args.SrcPath;
        DestPath = Directory.Exists(args.DestPath) ? args.DestPath : throw new Exception("E_INVALID_DEST_DIR");
    }
}

internal sealed record FhSTEPArgs(string SrcPath,
                                  string DestPath);

internal class FhSTEPArgsBinder : BinderBase<FhSTEPArgs> {
    private readonly Option<string> _opt_src_path;
    private readonly Option<string> _opt_dest_path;

    public FhSTEPArgsBinder(Option<string> opt_file_path,
                            Option<string> opt_dest_path) {
        _opt_src_path  = opt_file_path;
        _opt_dest_path = opt_dest_path;
    }

    protected override FhSTEPArgs GetBoundValue(BindingContext bindingContext) {
        string srcPath    = bindingContext.ParseResult.GetValueForOption(_opt_src_path) ?? throw new Exception("E_CLI_ARG_NULL");
        string destPath   = bindingContext.ParseResult.GetValueForOption(_opt_dest_path) ?? throw new Exception("E_CLI_ARG_NULL");

        return new FhSTEPArgs(srcPath, destPath);
    }
}
