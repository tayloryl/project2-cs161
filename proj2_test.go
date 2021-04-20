package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user")
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	// Check that fields of user are correctly initialized.

	//Own tests start here
	_, err = InitUser("alice", "fubar") //it should error since Alice already registered
	if err == nil {
		t.Error("User already exists", err)
		return
	}
	t.Log("Successfully handled duplicate user.")

}

func TestGetUser(t *testing.T) {
	clear()
	t.Log("GetUser Test")

	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err = GetUser("bob", "fubar")
	if err == nil {
		t.Error("Validated invalid login attempt: user does not exist.")
		return
	}
	t.Log("Successfully invalidated wrong password.")

	_, err = GetUser("alice", "wrong")
	if err == nil {
		t.Error("Validated invalid login attempt: wrong password.")
		return
	}
	t.Log("Successfully countered wrong password.")

	alice, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get valid user.", err)
		return
	}
	t.Log("Successfully retrieved valid user.")

	//Now check if the user data is the same

	if !reflect.DeepEqual(u, alice) {
		t.Error("Failed to get user data properly, it is not the same.")
		return
	}
	t.Log("Succesfully retrieved correct user data.")

	//Datastore tampering: lets change Alice's user struct
	_ = userlib.DatastoreGetMap()
	//cant assume staff user struct has certain fields
	/*
		dataStore[u.UUID_] = []byte("Changed Alice's user profile!")
		_, err = GetUser("alice", "fubar")
		if err == nil {
			t.Error("Validated an invalid login attempt: tampered user data.")
			return
		}
		t.Log("Succesfully preserved integrity of user data.")
	*/

}

func TestStorageAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	err_append := u.AppendFile("file1", []byte("Second file"))
	if err_append != nil {
		t.Error("Failed to append file", err_append)
		return
	}
	t.Log("Succesfully appended file.")

	err_append2 := u.AppendFile("file2", []byte("No file to append to."))
	if err_append2 == nil {
		t.Error("Did not error when file was not found.")
	}
	t.Log("Succesfully countered non-existent file.")

	v = append(v, []byte("Second file")...) //update v since we apended file

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	t.Log("Succesfully uploaded and downloaded file.")
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
	t.Log("Success: downloaded file is the same!")
}

func TestSingleUserAppend(t *testing.T) {
	clear()
	// taken from public ag tests
	file1data := []byte("File 1 data woohoo")
	file1dataAppend1 := []byte(" here is more yeet")
	file1dataAppend2 := []byte(" and even more!!")

	u, _ := InitUser("nick", "weaver")
	u.StoreFile("file1", file1data)
	u.AppendFile("file1", file1dataAppend1)
	u.AppendFile("file1", file1dataAppend2)

	t.Log("Succesfully appended two files.")

}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}
