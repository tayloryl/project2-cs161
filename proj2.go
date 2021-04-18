package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	"strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// User is the structure definition for a user record.
type User struct {
	Username string
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
	PasswordHash []byte // store password as a hash with salt
	UUID_        uuid.UUID
	Filespace    map[string]FileKey //keeps track of users files
	PrivSignKey  userlib.DSSignKey  //used for digital signatures
	EncKey       []byte             //used for encryption
}

type FileKey struct { //accesses all components of a related file
	keyId uuid.UUID //generate hashed UUID, use HKDF later to generate UUIDs for related files
	//owner    []byte
	enc_key  []byte //encryption key for all file elements
	hmac_key []byte //hmac key to generate hmac tags for each file elem
	numFiles int    //number of appends
}

type FileElem struct {
	fileID   uuid.UUID // generate from fileKey UUID
	filedata []byte
	file_ind int //0-indexed, represents number of file in file contents
}

//Helper function to make plaintext a multiple of block size (16 bytes)
//Dependin on mode (add, remove) return padded or unpadded data
func PKCS(data []byte, mode string) (padded_data []byte) {
	var pad_num int

	if mode == "add" {
		rem := len(data) % userlib.AESBlockSizeBytes
		pad_num = userlib.AESBlockSizeBytes - rem //number to pad by
		//pad := make([]byte, pad_num)              //pad array we are appending later
		padded_data = data[:]
		for i := 0; i < pad_num; i++ {
			//pad = append(pad, byte(pad_num))
			padded_data = append(padded_data, byte(pad_num))
		}

		//userlib.DebugMsg("%d", padded_data)
	} else { //remove padding
		//last byte is amount of padding there is
		//ex: d = [1022] means 2 bytes of padding so return d[:2] which is [10]

		num := len(data) - 1
		pad_num = len(data) - int(data[num]) //piazza: convert to byte > hex string > int?
		padded_data = data[:pad_num]
	}

	return padded_data
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	var verify_key userlib.DSVerifyKey //for digital signature verification
	userdataptr = &userdata

	//RETURN ERROR IF USERNAME EXISTS, must generate UUID first
	pw_hash := userlib.Argon2Key([]byte(password), []byte(username), 16)
	key_gen, _ := userlib.HMACEval(pw_hash, []byte(username))
	key_gen = key_gen[:16]
	uuid, _ := uuid.FromBytes(key_gen)  // byte slice since HMACEval produces 64 byte HMAC
	_, ok := userlib.DatastoreGet(uuid) // shouldnt exist

	if ok {
		return nil, errors.New("Username already exists")
	}

	userdata.Username = username
	//password hashing: salt = username
	userdata.PasswordHash = pw_hash
	//use hashed password to generate UUID/rest of keys
	userdata.UUID_ = uuid

	//generate private signing key
	userdata.PrivSignKey, verify_key, _ = userlib.DSKeyGen()
	userlib.KeystoreSet(username, verify_key) // store public RSA key in KeyStore
	//generate private encryption key
	enc_pw := append(pw_hash, []byte("encryption")...)
	userdata.EncKey = userlib.Argon2Key(enc_pw, []byte(username), 16)

	//create filespace for future use
	userdata.Filespace = make(map[string]FileKey)

	//marshal, generate HMAC + encrypt, and send to datastore
	user_bytes, _ := json.Marshal(userdata)

	hmac_pw := append([]byte(password), []byte("mac")...)
	hmac_key := userlib.Argon2Key(hmac_pw, []byte(username), 16)

	enc_IV := userlib.RandomBytes(userlib.AESBlockSizeBytes) //if IV isnt random, not secure
	enc_data := userlib.SymEnc(userdata.EncKey, enc_IV, PKCS(user_bytes, "add"))
	ds, _ := userlib.HMACEval(hmac_key, enc_data)

	enc_data_hmac := append(enc_data, ds...) //append HMAC at end of encrypted data
	userlib.DatastoreSet(userdata.UUID_, enc_data_hmac)

	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	//Assume UNIQUE usernames
	_, user_exist := userlib.KeystoreGet(username)
	if !user_exist {
		return nil, errors.New("User does not exist.")
	}

	//check password is valid
	pw_hash := userlib.Argon2Key([]byte(password), []byte(username), 16)
	key_gen, _ := userlib.HMACEval(pw_hash, []byte(username))
	key_gen = key_gen[:16]
	uuid, _ := uuid.FromBytes(key_gen)          //should generate same UUID if password is same
	user_json, ok := userlib.DatastoreGet(uuid) //retrieve the marshaled user info

	if !ok {
		return nil, errors.New("Invaild password!")
	}
	if len(user_json) < userlib.HashSizeBytes {
		//automatically return error, file has been changed
		return nil, errors.New("User data length has changed.")
	}
	len_data := len(user_json) - userlib.HashSizeBytes
	just_user := user_json[:len_data] //remove HMAC for later use

	//check integrity through HMAC: remember HMAC appended at end of file (last 16 bytes)
	mac := user_json[len_data:]

	//compute mac to set equal
	hmac_pw := append([]byte(password), []byte("mac")...)
	hmac_key := userlib.Argon2Key(hmac_pw, []byte(username), 16)
	correct_mac, _ := userlib.HMACEval(hmac_key, just_user)

	if !userlib.HMACEqual(correct_mac, mac) {
		return nil, errors.New("User has been compromised.")
	}

	//if no errors, return user! depad, decrypt and then unmarshal
	dec_pw := append(pw_hash, []byte("encryption")...)
	decKey := userlib.Argon2Key(dec_pw, []byte(username), 16)

	userdata_padded := userlib.SymDec(decKey, just_user)
	//depad
	userdata_final := PKCS(userdata_padded, "remove")
	//userlib.DebugMsg("%v\n", userdata_final)
	err = json.Unmarshal(userdata_final, &userdata)

	if err != nil {
		return nil, errors.New("Error unmarshaling data.")
	}

	return userdataptr, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
/* Stores file persistently for future retrieval. If a user calls StoreFile() on a
filename that already exists, the content of the existing file is overwritten. No
need to account for version control. */
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	var fileKey FileKey
	var fileElem FileElem
	//TODO: This is a toy implementation.
	/**
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	jsonData, _ := json.Marshal(data)
	userlib.DatastoreSet(storageKey, jsonData)
	*/
	//End of toy implementation
	//2 cases: already exists, doesnt exist : create new file, encrypt using SymEnc and marshal it
	fileKey, exists := userdata.Filespace[filename]
	if !exists {
		//create new file
		//creating the UUID for the FileKey
		storageKey := userlib.RandomBytes(16)
		fileKey.keyId, _ = uuid.FromBytes(storageKey)

		enc_key, _ := userlib.HashKDF(storageKey, []byte("encryption"))
		fileKey.enc_key = enc_key[:16]
		hmac_key, _ := userlib.HashKDF(storageKey, []byte("mac"))
		fileKey.hmac_key = hmac_key[:16]
		fileKey.numFiles = 1
		//add to users file space
		userdata.Filespace[filename] = fileKey

		//now generate first file element
		fileElem.file_ind = 0
		key_msg := filename + strconv.Itoa(fileElem.file_ind)
		key_bytes, _ := userlib.HMACEval(fileKey.hmac_key, []byte(key_msg))
		fileElem.fileID, _ = uuid.FromBytes(key_bytes[:16]) //new file ID based on file index and original fileKey
		fileElem.filedata = data

		//now encrypt the FileKey, FileElem, add HMACs, and send to datastore
		fk_marshal, _ := json.Marshal(fileKey)
		fe_marshal, _ := json.Marshal(fileElem)

		fk_IV := userlib.RandomBytes(userlib.AESBlockSizeBytes) //if IV isnt random, not secure
		fe_IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
		enc_fileKey := userlib.SymEnc(fileKey.enc_key, fk_IV, PKCS(fk_marshal, "add"))
		enc_fileElem := userlib.SymEnc(fileKey.enc_key, fe_IV, PKCS(fe_marshal, "add"))

		fk_hmac, _ := userlib.HMACEval(fileKey.hmac_key, enc_fileKey)
		fe_hmac, _ := userlib.HMACEval(fileKey.hmac_key, enc_fileElem)

		enc_fileKey = append(enc_fileKey, fk_hmac...)
		enc_fileElem = append(enc_fileElem, fe_hmac...)
		userlib.DatastoreSet(fileKey.keyId, enc_fileKey)
		userlib.DatastoreSet(fileElem.fileID, enc_fileElem)
	} else {

	}

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
//cant encrypt/decrypt entire file again, entire file doesnt need to be stored as one thing
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(dataJSON, &dataBytes)
	return dataBytes, nil

}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	return
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	return nil
}

// RevokeFile is documented at: ONLY OWNER REVOKES
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}
