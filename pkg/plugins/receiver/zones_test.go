package receiver

import (
	"fmt"
	"testing"
)

func TestDetectChangedRRset(t *testing.T) {

	// we need some tests for RRset compare function
	type TTest struct {
		uuid    string
		enabled bool
		rrset1  string
		rrset2  string
		result  bool
	}

	var Tests = []TTest{
		{
			"1b75bc3e-5b01-4aaa-b01e-198d9eb61507",
			true,
			`
			av-iva.mail.yandex.net.	7200    IN      A       5.255.227.187
			`,
			`
			av-iva.mail.yandex.net.	7200	IN	A	5.255.227.187
			`,
			true,
		},
		{
			"47b26903-e1d5-49e5-860e-92950bdc52bb",
			true,
			`
                        `,
			`
                        av-iva.mail.yandex.net. 7200    IN      A       5.255.227.187
                        `,
			false,
		},
		{
			"5e3a9f69-a55c-4674-9f52-b61fee6c863f",
			true,
			`
                        av-iva.mail.yandex.net. 7200    IN      A       5.255.227.187
                        `,
			`
                        `,
			false,
		},
		{
			"1b75bc3e-5b01-4aaa-b01e-198d9eb61507",
			true,
			`
                        `,
			`
                        `,
			true,
		},
		{
			"2e5367ea-c6bc-4124-a8cd-8c931c49f4df",
			true,
			`
                        av-iva.mail.yandex.net. 7200    IN      A       5.255.227.187
                        av-iva.mail.yandex.net. 7200    IN      A       5.255.227.188
                        `,
			`
                        av-iva.mail.yandex.net. 7200    IN      A       5.255.227.187
                        `,
			false,
		},
		{
			"9319852b-a84b-4e58-9ad7-7aa5abce00b4",
			true,
			`
                        av-iva.mail.yandex.net. 7200    IN      A       5.255.227.187
                        av-iva.mail.yandex.net. 7200    IN      A       5.255.227.188
                        `,
			`
                        av-iva.mail.yandex.net. 7200    IN      A       5.255.227.188
                        av-iva.mail.yandex.net. 7200    IN      A       5.255.227.187
                        `,
			true,
		},
		{
			"1dceb7ac-d5e0-4f7c-8c28-ce60b8928955",
			true,
			`
                        av-iva.mail.yandex.net. 7200    IN      A       5.255.227.188
                        `,
			`
			av-iva.mail.yandex.net. 7200    IN      AAAA	2a02::1
                        `,
			false,
		},
	}

	var state TZoneState

	for _, Test := range Tests {
		if !Test.enabled {
			continue
		}

		rrset1, err := NewXFR(Test.rrset1)
		if err != nil {
			fmt.Printf("Test:'%s' xfr rrset1  parse FAILED (ERROR), err:'%s'\n", Test.uuid, err)
			t.Error(
				"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
				"\nRRSET1", fmt.Sprintf("\nrrest1:'\n%s\n'", Test.rrset1),
				"\nGOT", fmt.Sprintf("\nerr:'%s'", err),
			)
			continue
		}

		rrset2, err := NewXFR(Test.rrset2)
		if err != nil {
			fmt.Printf("Test:'%s' xfr rrset2 parse FAILED (ERROR), err:'%s'\n", Test.uuid, err)
			t.Error(
				"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
				"\nRRSET2", fmt.Sprintf("\nrrest2:'\n%s\n'", Test.rrset2),
				"\nGOT", fmt.Sprintf("\nerr:'%s'", err),
			)
			continue
		}

		changed := state.DetectChangedRRset(rrset1, rrset2)
		if changed != Test.result {
			fmt.Printf("Test:'%s' detect changed failed rrset1:'%d' rrset2:'%d'\n",
				Test.uuid, len(rrset1), len(rrset2))
			t.Error(
				"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
				"\nRRSET1", fmt.Sprintf("\nrrest1:'\n%s\n'", Test.rrset1),
				"\nRRSET2", fmt.Sprintf("\nrrest2:'\n%s\n'", Test.rrset2),
				"\nEXPECTED", fmt.Sprintf("\n'%t'", Test.result),
				"\nGOT", fmt.Sprintf("\n'%t'", changed),
			)
			continue
		}

		fmt.Printf("Test:'%s' rrset changed passed OK\n", Test.uuid)
	}
}
