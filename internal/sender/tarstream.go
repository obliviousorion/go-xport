package sender

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// countWriter counts the number of bytes written to it.
type countWriter struct {
	count uint64
}

func (c *countWriter) Write(p []byte) (int, error) {
	c.count += uint64(len(p))
	return len(p), nil
}

type zeroReader struct{}

func (z zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// CalculateTarSize computes the exact uncompressed tar archive size for a directory
// including tar headers, padding, and end-of-archive blocks.
func CalculateTarSize(dirPath string) (uint64, error) {
	cw := &countWriter{}
	tw := tar.NewWriter(cw)

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(dirPath, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("failed to create tar header for %s: %w", path, err)
		}
		hdr.Name = filepath.ToSlash(relPath)

		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("failed to write tar header for %s: %w", path, err)
		}

		if info.Mode().IsRegular() && info.Size() > 0 {
			if _, err := io.CopyN(tw, zeroReader{}, info.Size()); err != nil {
				return fmt.Errorf("failed to simulate write for %s: %w", path, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	if err := tw.Close(); err != nil {
		return 0, err
	}

	return cw.count, nil
}

// StreamTar creates an on-the-fly streaming tar reader for a directory using io.Pipe.
// No intermediate tar archive is written to disk.
func StreamTar(dirPath string) (io.ReadCloser, error) {
	info, err := os.Stat(dirPath)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dirPath)
	}

	pr, pw := io.Pipe()

	go func() {
		tw := tar.NewWriter(pw)
		walkErr := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			relPath, err := filepath.Rel(dirPath, path)
			if err != nil {
				return err
			}
			if relPath == "." {
				return nil
			}

			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return fmt.Errorf("header error for %s: %w", path, err)
			}
			hdr.Name = filepath.ToSlash(relPath)

			if err := tw.WriteHeader(hdr); err != nil {
				return fmt.Errorf("write header error for %s: %w", path, err)
			}

			if info.Mode().IsRegular() {
				f, err := os.Open(path)
				if err != nil {
					return fmt.Errorf("open file error for %s: %w", path, err)
				}
				_, copyErr := io.Copy(tw, f)
				_ = f.Close()
				if copyErr != nil {
					return fmt.Errorf("copy stream error for %s: %w", path, copyErr)
				}
			}
			return nil
		})

		if walkErr != nil {
			_ = tw.Close()
			_ = pw.CloseWithError(walkErr)
			return
		}

		if closeErr := tw.Close(); closeErr != nil {
			_ = pw.CloseWithError(closeErr)
			return
		}

		_ = pw.Close()
	}()

	return pr, nil
}
