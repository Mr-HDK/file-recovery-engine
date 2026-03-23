using FileRecovery.WindowsApp.Core.Models;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed class SourceDestinationSafetyValidator
{
    private readonly IStorageTopologyService _topologyService;

    public SourceDestinationSafetyValidator(IStorageTopologyService topologyService)
    {
        _topologyService = topologyService;
    }

    public ValidationResult Validate(SourceCandidate? source, string? destinationPath, bool isElevated)
    {
        var issues = new List<ValidationIssue>();

        if (source is null)
        {
            issues.Add(new ValidationIssue(ValidationSeverity.Error, "source-missing", "Select a source before starting recovery."));
            return new ValidationResult(issues);
        }

        if (string.IsNullOrWhiteSpace(destinationPath))
        {
            issues.Add(new ValidationIssue(ValidationSeverity.Error, "destination-missing", "Select a destination folder."));
            return new ValidationResult(issues);
        }

        var destinationFullPath = Path.GetFullPath(destinationPath);
        if (!Directory.Exists(destinationFullPath))
        {
            issues.Add(new ValidationIssue(ValidationSeverity.Error, "destination-not-found", "Destination folder does not exist."));
            return new ValidationResult(issues);
        }

        var destinationVolume = _topologyService.TryGetVolumeIdFromPath(destinationFullPath);
        var destinationDisk = _topologyService.TryGetDiskIndexFromPath(destinationFullPath);

        if (source.Kind != RecoverySourceKind.ImageFile && string.IsNullOrWhiteSpace(source.DevicePath))
        {
            issues.Add(new ValidationIssue(
                ValidationSeverity.Error,
                "source-device-missing",
                "Selected source does not expose a readable device path."));
            return new ValidationResult(issues);
        }

        switch (source.Kind)
        {
            case RecoverySourceKind.Volume:
            case RecoverySourceKind.Partition:
                ValidateVolumeSource(source, destinationVolume, issues);
                break;
            case RecoverySourceKind.PhysicalDisk:
                ValidatePhysicalDiskSource(source, destinationDisk, issues);
                break;
            case RecoverySourceKind.ImageFile:
                ValidateImageSource(source, destinationVolume, issues);
                break;
        }

        if (!isElevated)
        {
            issues.Add(new ValidationIssue(
                ValidationSeverity.Warning,
                "not-elevated",
                "Application is not elevated. Raw device access may fail for some sources."));
        }

        if (issues.All(i => i.Severity != ValidationSeverity.Error))
        {
            issues.Add(new ValidationIssue(ValidationSeverity.Info, "validation-passed", "Safety checks passed."));
        }

        return new ValidationResult(issues);
    }

    private void ValidateVolumeSource(
        SourceCandidate source,
        string? destinationVolume,
        List<ValidationIssue> issues)
    {
        var sourceVolume = source.VolumeIdentity;

        if (sourceVolume is null && source.SourcePath is not null)
        {
            sourceVolume = _topologyService.TryGetVolumeIdFromPath(source.SourcePath);
        }

        if (sourceVolume is null || destinationVolume is null)
        {
            issues.Add(new ValidationIssue(
                ValidationSeverity.Warning,
                "volume-unresolved",
                "Could not fully resolve source/destination volume identity."));
            return;
        }

        if (string.Equals(sourceVolume, destinationVolume, StringComparison.OrdinalIgnoreCase))
        {
            issues.Add(new ValidationIssue(
                ValidationSeverity.Error,
                "same-volume",
                "Destination must be on a different volume than the source."));
        }
    }

    private static void ValidatePhysicalDiskSource(
        SourceCandidate source,
        int? destinationDisk,
        List<ValidationIssue> issues)
    {
        if (!source.DiskIndex.HasValue || !destinationDisk.HasValue)
        {
            issues.Add(new ValidationIssue(
                ValidationSeverity.Warning,
                "disk-unresolved",
                "Could not fully resolve source/destination disk index."));
            return;
        }

        if (source.DiskIndex.Value == destinationDisk.Value)
        {
            issues.Add(new ValidationIssue(
                ValidationSeverity.Error,
                "same-disk",
                "Destination must be on a different physical disk than the source disk."));
        }
    }

    private void ValidateImageSource(
        SourceCandidate source,
        string? destinationVolume,
        List<ValidationIssue> issues)
    {
        if (source.SourcePath is null)
        {
            issues.Add(new ValidationIssue(
                ValidationSeverity.Error,
                "image-path-missing",
                "Image source path is unavailable."));
            return;
        }

        var sourceVolume = source.VolumeIdentity ?? _topologyService.TryGetVolumeIdFromPath(source.SourcePath);

        if (sourceVolume is null || destinationVolume is null)
        {
            issues.Add(new ValidationIssue(
                ValidationSeverity.Warning,
                "image-volume-unresolved",
                "Could not fully resolve source image and destination volume identity."));
            return;
        }

        if (string.Equals(sourceVolume, destinationVolume, StringComparison.OrdinalIgnoreCase))
        {
            issues.Add(new ValidationIssue(
                ValidationSeverity.Error,
                "same-volume-image",
                "Destination must be on a different volume than the source image file."));
        }
    }
}
