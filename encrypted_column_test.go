package encryptedcolumn

import "testing"

var encryptedColumnTests = []struct {
	key       string
	usePrefix bool
	in        string
	out       string
}{
	{
		key:       "0c2545f478d59485aa8ccc83d09101dbfb9a8e1924f4a5052e821f21cde476e2",
		usePrefix: true,
		out:       "Being a woman is a terribly difficult task, since it consists principally in dealing with men.",
		in:        "--ENCR--EQF9ytxYuYkRqViFG0f2fvsJX4vc5xfW0JEeFXLP0gaUevA5fLCMqdEGCtVTurSBkuFwRx8KdcS1d2cnq7I6inrwuiqOUdw9S8ca4KUhF4RKwmsKVVzqxAn3AxmgGscZYWMyODg2MGQ5ZTRlMmMxZA==",
	},
}

func TestNewEncryptedColumn(t *testing.T) {
	key := "whatever and ever amen don't forget my black t-shirt"
	col, _ := NewEncryptedColumn(key, true)

	if string(col.Key) != string([]byte(key)[:32]) {
		t.Fatalf(".Key %s != %s", string(col.Key), string([]byte(key)[:32]))
	}

	if col.Prefix != "--ENCR--" {
		t.Fatalf(".Prefix %s != \"--ENCR--\"", col.Prefix)
	}

	if col.Disable {
		t.Fatalf(".Disable true != false")
	}

	if !col.UsePrefix {
		t.Fatalf(".UsePrefix false != true")
	}
}

func TestEncryptedColumnLoad(t *testing.T) {
	for _, test := range encryptedColumnTests {
		col, _ := NewEncryptedColumn(test.key, test.usePrefix)
		out, err := col.Load(test.in)
		if err != nil {
			t.Fatalf("%s", err)
		}
		if out != test.out {
			t.Fatalf("out %q != %q", out, test.out)
		}
	}
}

func TestEncryptedColumnDump(t *testing.T) {
	for _, test := range encryptedColumnTests {
		col, _ := NewEncryptedColumn(test.key, test.usePrefix)
		encrypted, err := col.Dump(test.out)
		if err != nil {
			t.Fatalf("%s", err)
		}
		decrypted, _ := col.Load(encrypted)
		if decrypted != test.out {
			t.Fatalf("out %q != %q", decrypted, test.out)
		}
	}
}
