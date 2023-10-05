package services

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"

	reflectionv1 "cosmossdk.io/api/cosmos/reflection/v1"
	"github.com/cosmos/gogoproto/proto"
	protov2 "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// ReflectionService implements the cosmos.reflection.v1 service.
type ReflectionService struct {
	reflectionv1.UnimplementedReflectionServiceServer
	files *descriptorpb.FileDescriptorSet
}

func NewReflectionService() (*ReflectionService, error) {
	fds := &descriptorpb.FileDescriptorSet{}

	// load gogo proto file descriptors
	allFds := proto.AllFileDescriptors()
	haveFileDescriptor := map[string]bool{}
	for _, compressedBz := range allFds {
		rdr, err := gzip.NewReader(bytes.NewReader(compressedBz))
		if err != nil {
			return nil, err
		}

		bz, err := io.ReadAll(rdr)
		if err != nil {
			return nil, err
		}

		fd := &descriptorpb.FileDescriptorProto{}
		err = protov2.Unmarshal(bz, fd)
		if err != nil {
			return nil, err
		}

		fds.File = append(fds.File, fd)
		haveFileDescriptor[*fd.Name] = true
	}

	// load any protoregistry file descriptors not in gogo
	protoregistry.GlobalFiles.RangeFiles(func(fileDescriptor protoreflect.FileDescriptor) bool {
		if !haveFileDescriptor[fileDescriptor.Path()] {
			fds.File = append(fds.File, protodesc.ToFileDescriptorProto(fileDescriptor))
		}
		return true
	})

	// UNFORKINGTODO: sort not working with following error:
	// 	../go/pkg/mod/github.com/osmosis-labs/cosmos-sdk@v0.47.6-0.20231005201857-17a6e642571a/runtime/services/reflection.go:60:28:
	// type func(x *descriptorpb.FileDescriptorProto, y *descriptorpb.FileDescriptorProto) bool of func(x, y *descriptorpb.FileDescriptorProto)
	// bool {…} does not match inferred type func(a *descriptorpb.FileDescriptorProto, b *descriptorpb.FileDescriptorProto) int for func(a E, b E) int
	// make: *** [build] Error 1
	// slices.SortFunc(fds.File, func(x, y *descriptorpb.FileDescriptorProto) bool {
	// 	return *x.Name < *y.Name
	// })

	return &ReflectionService{files: fds}, nil
}

func (r ReflectionService) FileDescriptors(_ context.Context, _ *reflectionv1.FileDescriptorsRequest) (*reflectionv1.FileDescriptorsResponse, error) {
	return &reflectionv1.FileDescriptorsResponse{
		Files: r.files.File,
	}, nil
}

var _ reflectionv1.ReflectionServiceServer = &ReflectionService{}
