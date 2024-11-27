package imaging

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"os"
	"strings"
)

type PngInteractorInterface interface {
	AddTextChunkToFile(key string, value string, outputFileName string) error
	AddTextChunkToData(key string, value string, outputFileName string) error
	ReadAllMetadata() error
	FlattenImage() (bytes.Buffer, error)
}

type PngInteractor struct {
	Filename   string
	ImageBytes []byte
}

func NewPngInteractor(filename string) (*PngInteractor, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return &PngInteractor{
		Filename:   filename,
		ImageBytes: data,
	}, err
}

func (p *PngInteractor) AddTextChunkToFile(key string, value string, outputFileName string) error {
	file, err := os.Open(p.Filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Decode the PNG to check the image structure
	_, err = png.Decode(file)
	if err != nil {
		return err
	}

	// Open the file for writing the new image with metadata
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// Go back to the beginning the original file for reading as binary
	file.Seek(0, 0)
	data, err := os.ReadFile(p.Filename)
	if err != nil {
		return err
	}

	// Find the IEND chunk to add the text chunk before it
	// PNG chunks have a specific structure (length, type, data, CRC)
	buf := new(bytes.Buffer)

	// Write original image content
	buf.Write(data[:len(data)-12]) // Skip the IEND chunk

	// Create a new tEXt chunk with key-value metadata
	keyValue := key + "\x00" + value
	length := uint32(len(keyValue))
	binary.Write(buf, binary.BigEndian, length)
	buf.WriteString("tEXt")   // Chunk type (tEXt for metadata)
	buf.WriteString(keyValue) // The key-value data

	crc := crc32Checksum("tEXt" + keyValue) // Calculate CRC for chunk
	binary.Write(buf, binary.BigEndian, crc)

	// Rewrite IEND chunk at the end
	buf.Write(data[len(data)-12:])

	// Write final output to a new PNG file
	_, err = outputFile.Write(buf.Bytes())
	if err != nil {
		return err
	}

	fmt.Println("Metadata added and image saved as output.png")
	return nil
}

func (p *PngInteractor) AddTextChunkToData(key string, value string, outputFileName string) error {
	// Open the file for writing the new image with metadata
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// Find the IEND chunk to add the text chunk before it
	// PNG chunks have a specific structure (length, type, data, CRC)
	buf := new(bytes.Buffer)

	// Write original image content
	buf.Write(p.ImageBytes[:len(p.ImageBytes)-12]) // Skip the IEND chunk

	// Create a new tEXt chunk with key-value metadata
	keyValue := key + "\x00" + value
	length := uint32(len(keyValue))
	binary.Write(buf, binary.BigEndian, length)
	buf.WriteString("tEXt")   // Chunk type (tEXt for metadata)
	buf.WriteString(keyValue) // The key-value data

	crc := crc32Checksum("tEXt" + keyValue) // Calculate CRC for chunk
	binary.Write(buf, binary.BigEndian, crc)

	// Rewrite IEND chunk at the end
	buf.Write(p.ImageBytes[len(p.ImageBytes)-12:])

	// Write final output to a new PNG file
	_, err = outputFile.Write(buf.Bytes())
	if err != nil {
		return err
	}

	fmt.Println("Metadata added and image saved as output.png")
	return nil
}

func (p *PngInteractor) ReadAllMetadata() error {
	file, err := os.Open(p.Filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Check PNG signature
	var pngHeader [8]byte
	if _, err := file.Read(pngHeader[:]); err != nil {
		return fmt.Errorf("failed to read PNG signature: %w", err)
	}

	if string(pngHeader[:]) != "\x89PNG\r\n\x1a\n" {
		return fmt.Errorf("file is not a valid PNG")
	}

	// Read PNG chunks
	for {
		var length uint32
		if err := binary.Read(file, binary.BigEndian, &length); err != nil {
			return nil // Reached end of file
		}

		// Read chunk type (4 bytes)
		chunkType := make([]byte, 4)
		if _, err := file.Read(chunkType); err != nil {
			return fmt.Errorf("failed to read chunk type: %w", err)
		}

		// Read chunk data based on length
		chunkData := make([]byte, length)
		if _, err := file.Read(chunkData); err != nil {
			return fmt.Errorf("failed to read chunk data: %w", err)
		}

		// Read CRC (4 bytes)
		crc := make([]byte, 4)
		if _, err := file.Read(crc); err != nil {
			return fmt.Errorf("failed to read CRC: %w", err)
		}

		// Identify metadata chunks
		chunkTypeStr := string(chunkType)
		if chunkTypeStr == "tEXt" || chunkTypeStr == "zTXt" || chunkTypeStr == "iTXt" {
			fmt.Printf("%s chunk: ", chunkTypeStr)
			fmt.Printf("Metadata: %s\n", chunkData)
		}

		// End if IEND chunk is reached
		if chunkTypeStr == "IEND" {
			break
		}
	}

	return nil
}

func (p *PngInteractor) FindSignatureMetadata() (string, error) {
	file, err := os.Open(p.Filename)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Check PNG signature
	var pngHeader [8]byte
	if _, err := file.Read(pngHeader[:]); err != nil {
		return "", fmt.Errorf("failed to read PNG signature: %w", err)
	}

	if string(pngHeader[:]) != "\x89PNG\r\n\x1a\n" {
		return "", fmt.Errorf("file is not a valid PNG")
	}

	// Read PNG chunks
	for {
		var length uint32
		if err := binary.Read(file, binary.BigEndian, &length); err != nil {
			return "", nil // Reached end of file
		}

		// Read chunk type (4 bytes)
		chunkType := make([]byte, 4)
		if _, err := file.Read(chunkType); err != nil {
			return "", fmt.Errorf("failed to read chunk type: %w", err)
		}

		// Read chunk data based on length
		chunkData := make([]byte, length)
		if _, err := file.Read(chunkData); err != nil {
			return "", fmt.Errorf("failed to read chunk data: %w", err)
		}

		// Read CRC (4 bytes)
		crc := make([]byte, 4)
		if _, err := file.Read(crc); err != nil {
			return "", fmt.Errorf("failed to read CRC: %w", err)
		}

		// Identify metadata chunks
		chunkTypeStr := string(chunkType)
		metadata := string(chunkData)
		if strings.HasPrefix(metadata, "Signature\x00") {
			signature := metadata[len("Signature\x00"):] // Extract remainder after "Signature"
			return signature, nil
		}

		// End if IEND chunk is reached
		if chunkTypeStr == "IEND" {
			break
		}
	}

	return "", errors.New("signature tEXt chunk not found")
}

func (p *PngInteractor) FlattenImage() (bytes.Buffer, error) {
	// Read the image back and access the raw pixel data
	file, err := os.Open(p.Filename)
	if err != nil {
		fmt.Println("Error opening image:", err)
		return bytes.Buffer{}, err
	}
	defer file.Close()

	// Decode the PNG image file
	decodedImg, err := png.Decode(file)
	if err != nil {
		fmt.Println("Error decoding PNG:", err)
		return bytes.Buffer{}, err
	}

	// Convert the image to RGBA if it's not already in that format
	rgbaImg, ok := decodedImg.(*image.RGBA)
	fmt.Printf("Dimensions: %dx%d\n", rgbaImg.Bounds().Max.X, rgbaImg.Bounds().Max.Y)
	if !ok {
		// If not RGBA, create a new RGBA image and draw the decoded image into it
		bounds := decodedImg.Bounds()

		rgbaImg = image.NewRGBA(bounds)
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				rgbaImg.Set(x, y, decodedImg.At(x, y))
			}
		}
	}

	// Access the pixel data and flatten them to a buffer
	var buf bytes.Buffer
	for y := 0; y < rgbaImg.Bounds().Dy(); y++ {
		for x := 0; x < rgbaImg.Bounds().Dx(); x++ {
			r, g, b, a := rgbaImg.At(x, y).RGBA()

			// Store the pixel values as 8-bit (since RGBA returns 16-bit)
			buf.WriteByte(byte(r >> 8))
			buf.WriteByte(byte(g >> 8))
			buf.WriteByte(byte(b >> 8))
			buf.WriteByte(byte(a >> 8))
		}
	}

	return buf, nil
}

func CreateSquareImage(sideLength int, outputFilename string) error {
	width := sideLength
	height := sideLength

	upLeft := image.Point{0, 0}
	lowRight := image.Point{width, height}

	img := image.NewRGBA(image.Rectangle{upLeft, lowRight})

	// Red, Green, Blue, Alpha uint8 values
	cyan := color.RGBA{100, 200, 200, 0xff}

	// Set pixel colors
	for x := 0; x < width; x++ {
		for y := 0; y < height; y++ {
			switch {
			case x < width/2 && y < height/2: // upper left quadrant
				img.Set(x, y, cyan)
			case x >= width/2 && y >= height/2: // lower right quadrant
				img.Set(x, y, color.White)
			default:
				img.Set(x, y, cyan) // other two quadrants
			}
		}
	}

	// Encode as PNG
	f, err := os.Create(outputFilename)
	if err != nil {
		fmt.Println("Could not save to file")
		return err
	}
	png.Encode(f, img)
	f.Close()

	return nil
}

func crc32Checksum(data string) uint32 {
	// Function to compute CRC-32 checksum for PNG chunk
	return crc32.ChecksumIEEE([]byte(data))
}
