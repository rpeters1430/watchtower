package types

// ImageDiskUsage holds aggregated Docker image storage usage from GET /system/df.
type ImageDiskUsage struct {
	// TotalSize is the number of bytes used by images.
	TotalSize int64
	// Reclaimable is the number of bytes that unused images could free.
	Reclaimable int64
	// TotalCount is the number of images.
	TotalCount int64
	// ActiveCount is the number of images in use by containers.
	ActiveCount int64
}

// ImagePruneReport is what removing unused images freed.
type ImagePruneReport struct {
	// ImagesDeleted is the number of image IDs the daemon deleted.
	ImagesDeleted int
	// Untagged lists the image references the daemon untagged.
	Untagged []string
	// SpaceReclaimed is the number of bytes freed.
	SpaceReclaimed int64
}
