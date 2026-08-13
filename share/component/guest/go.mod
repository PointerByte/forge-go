module wit_component

go 1.25.0

require go.bytecodealliance.org/pkg v0.2.2

require (
	github.com/PointerByte/forge-go/share/component v0.0.0
	github.com/PointerByte/forge-go/share/portable v0.0.0
	github.com/apparentlymart/go-userdirs v0.0.0-20200915174352-b0c018a67c13 // indirect
	github.com/bytecodealliance/componentize-go v0.4.0 // indirect
	github.com/gofrs/flock v0.13.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
)

tool github.com/bytecodealliance/componentize-go

replace github.com/PointerByte/forge-go/share/component => ..

replace github.com/PointerByte/forge-go/share/portable => ../../portable
