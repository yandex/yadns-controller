package receiver

import (
	"fmt"
	"testing"

	"github.com/yandex/yadns-controller/pkg/plugins/offloader"
)

func TestUnpackName(t *testing.T) {

	type TTest struct {
		uuid    string
		enabled bool
		pqname  offloader.RRQname
		qname   string
		err     bool
	}

	var Tests = []TTest{
		{
			"ce936b53-c33a-4ade-ae55-9aec305b43b1",
			true,
			offloader.RRQname{0x4, 0x74, 0x65, 0x73, 0x74, 0x6, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x3, 0x6e, 0x65, 0x74},
			"test.yandex.net",
			false,
		},
		{
			"a3c42bff-e0ff-4e9c-9984-7b9d9896ceb4",
			true,
			offloader.RRQname{0x4, 0x74, 0x65, 0x73, 0x74},
			"test",
			false,
		},
		{
			"69f35edd-fa88-4634-b9f4-d73b26822aff",
			true,
			offloader.RRQname{},
			"",
			true,
		},
		{
			"5bbb05a0-3779-43b1-9cfd-1d1151eb4081",
			true,
			offloader.RRQname{0x1, 0x61},
			"a",
			false,
		},
	}

	for _, Test := range Tests {
		if !Test.enabled {
			continue
		}

		name, err := UnpackName(Test.pqname)

		if Test.err && err != nil {
			fmt.Printf("Test:'%s' pqname:'%s' OK (EXPECTED ERROR)\n", Test.uuid, Test.pqname.AsByteString())
			continue
		}

		if !Test.err && err != nil {
			fmt.Printf("Test:'%s' pqname:'%s' FAILED (ERROR)\n", Test.uuid, Test.pqname.AsByteString())
			t.Error(
				"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
				"\nFOR TEST", fmt.Sprintf("\npqname:'%s'", Test.pqname.AsByteString()),
				"\nEXPECTED", fmt.Sprintf("\nerr:'%t'", Test.err),
				"\nGOT", fmt.Sprintf("\nerr:'%s'", err),
			)
			continue
		}

		if !Test.err && err == nil {
			if Test.qname != name {
				fmt.Printf("Test:'%s' pqname:'%s' FAILED (RETURN VALUE)\n", Test.uuid, Test.pqname.AsByteString())
				t.Error(
					"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
					"\nEXPECTED", fmt.Sprintf("\nunpacked:'%s'", Test.qname),
					"\nFOR TEST", fmt.Sprintf("\npqname:'%s'", Test.pqname.AsByteString()),
					"\nGOT", fmt.Sprintf("\nunpacked:'%s'", name),
				)
				continue
			}
		}

		fmt.Printf("Test:'%s' pqname:'%s' as '%s' PASSED\n", Test.uuid, Test.pqname.AsByteString(), name)
	}
}

func TestPackName(t *testing.T) {

	// checking if qname is packed as pqname or
	// it could be expected error (see err as true)
	type TTest struct {
		uuid    string
		enabled bool
		qname   string
		pqname  offloader.RRQname
		err     bool
	}

	var Tests = []TTest{
		{
			"0de8559b-c05d-4f2a-80fe-46177f90b0f9",
			true,
			"test.yandex.net",
			offloader.RRQname{0x4, 0x74, 0x65, 0x73, 0x74, 0x6, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x3, 0x6e, 0x65, 0x74},
			false,
		},
		{
			"0c59262a-4775-4985-8f7c-4766c35c4689",
			true,
			"test.yandex.net.",
			offloader.RRQname{0x4, 0x74, 0x65, 0x73, 0x74, 0x6, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x3, 0x6e, 0x65, 0x74},
			false,
		},
		{
			"296ea05a-7efd-4b42-a748-04ae82ff9ba2",
			true,
			"test.",
			offloader.RRQname{0x4, 0x74, 0x65, 0x73, 0x74},
			false,
		},
		{
			"866d44c6-0db6-4947-8de4-fb6a71edfd56",
			true,
			"test",
			offloader.RRQname{0x4, 0x74, 0x65, 0x73, 0x74},
			false,
		},
		{
			"2f11f261-84bb-4827-9f87-8223ab897b71",
			true,
			".",
			offloader.RRQname{},
			true,
		},
		{
			"91b2923f-40be-42a8-bdb9-5be7190dcd41",
			true,
			"",
			offloader.RRQname{},
			true,
		},
		{
			"82556401-3e56-458f-af55-b8305287ed36",
			true,
			"a",
			offloader.RRQname{0x1, 0x61},
			false,
		},
		{
			"b42ee39c-34bf-4236-ab0f-6720484a0e3f",
			true,
			string([]byte{0x61, 0x0}),
			offloader.RRQname{0x1, 0x61},
			false,
		},
		{
			"cf31b4c5-1115-4689-b0de-5bc723974f75",
			true,
			string([]byte{0x0}),
			offloader.RRQname{0x0},
			false,
		},
	}

	for _, Test := range Tests {
		if !Test.enabled {
			continue
		}
		pqname, err := PackName(Test.qname)

		if Test.err && err != nil {
			fmt.Printf("Test:'%s' qname:'%s' OK (EXPECTED ERROR)\n", Test.uuid, Test.qname)
			continue
		}

		if !Test.err && err != nil {
			fmt.Printf("Test:'%s' qname:'%s' FAILED (ERROR)\n", Test.uuid, Test.qname)
			t.Error(
				"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
				"\nFOR TEST", fmt.Sprintf("\nqname:'%s'", Test.qname),
				"\nEXPECTED", fmt.Sprintf("\nerr:'%t'", Test.err),
				"\nGOT", fmt.Sprintf("\nerr:'%s'", err),
			)
			continue
		}

		if !Test.err && err == nil {
			if Test.pqname != pqname {
				fmt.Printf("Test:'%s' qname:'%s' FAILED (RETURN VALUE)\n", Test.uuid, Test.qname)
				t.Error(
					"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
					"\nFOR TEST", fmt.Sprintf("\nqname:'%s'", Test.qname),
					"\nEXPECTED", fmt.Sprintf("\npacked:'%s'", Test.pqname.AsByteString()),
					"\nGOT", fmt.Sprintf("\npacked:'%s'", pqname.AsByteString()),
				)
				continue
			}
		}

		fmt.Printf("Test:'%s' qname:'%s' as '%s' PASSED\n", Test.uuid, Test.qname, pqname.AsByteString())
	}

}
