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

// User is the structure definition for a user record.
type User struct {
	Username string
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
	PasswordHash []byte // store password as a hash with salt
	UUID_        uuid.UUID
	Filespace    map[string]FileKey   //keeps track of ALL users files (owned, shared, etc)
	FilesOwned   map[string]FileKey   //all files that this user OWNS
	AccessTokens map[string]uuid.UUID //basically all files shared with user
	PrivRSAKey   userlib.PKEDecKey    //used for shareFile
	PrivSignKey  userlib.DSSignKey    //used for RSA signature
	EncKey       []byte               //used for encryption
	HMACKey      []byte               //used for validating files
}

type FileKey struct { //accesses all components of a related file
	KeyId       uuid.UUID           //generate hashed UUID, use HKDF later to generate UUIDs for related files
	SharedUsers map[string][]string //each key is a user shared directly with owner
	//the value of SharedUsers is a list of users THAT user has shared with
	UserTokens map[string]uuid.UUID //maps users to their access token
	Enc_key    []byte               //encryption key for all file elements
	HMAC_key   []byte               //hmac key to generate hmac tags for each file elem
	NumFiles   int                  //number of appends
}

//each FileElem is AES-CBC encrypted using the FileKey encryption key
type FileElem struct {
	FileID   uuid.UUID // generate from fileKey UUID
	Filedata []byte
	File_ind int //1-indexed, represents number of file in file contents
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	var verify_key userlib.DSVerifyKey //for digital signature verification
	userdataptr = &userdata

	if username == "" || password == "" {
		return nil, errors.New("Empty username or password")
	}
	//RETURN ERROR IF USERNAME EXISTS, must generate UUID first
	pw_hash := userlib.Argon2Key([]byte(password), []byte(username), 16)
	key_gen, _ := userlib.HMACEval(pw_hash, []byte(username))
	key_gen = key_gen[:16]
	uuid_, _ := uuid.FromBytes(key_gen)  // byte slice since HMACEval produces 64 byte HMAC
	_, ok := userlib.DatastoreGet(uuid_) // shouldnt exist

	if ok {
		return nil, errors.New("Username already exists")
	}

	userdata.Username = username
	//password hashing: salt = username
	userdata.PasswordHash = pw_hash
	//use hashed password to generate UUID/rest of keys
	userdata.UUID_ = uuid_

	//generate private signing key
	var public_RSAKey userlib.PKEEncKey
	userdata.PrivSignKey, verify_key, _ = userlib.DSKeyGen()
	public_RSAKey, userdata.PrivRSAKey, _ = userlib.PKEKeyGen()
	userlib.KeystoreSet(username+"public_key", public_RSAKey) //store public key in store
	userlib.KeystoreSet(username+"ds", verify_key)            // store public signature in store
	//generate private encryption key
	enc_pw := append(pw_hash, []byte("encryption")...)
	userdata.EncKey = userlib.Argon2Key(enc_pw, []byte(username), 16)

	//create filespace for future use
	userdata.Filespace = make(map[string]FileKey)
	userdata.FilesOwned = make(map[string]FileKey)
	userdata.AccessTokens = make(map[string]uuid.UUID)
	//need HMAC for later
	hmac_pw := append([]byte(password), []byte("mac")...)
	hmac_key := userlib.Argon2Key(hmac_pw, []byte(username), 16)
	userdata.HMACKey = hmac_key

	//marshal, generate HMAC + encrypt, and send to datastore
	user_bytes, _ := json.Marshal(userdata)

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

	//verifies there is a user to begin with since KeyStore is secure
	_, user_exist := userlib.KeystoreGet(username + "ds")
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
		return nil, errors.New("Invalid password!")
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

//Helper function to support multple sessions. Can get user with current user struct
//basically same as getUser just skips some checks
func GetLatestUser(uuid uuid.UUID, pw_hash []byte, hmac_key []byte, decKey []byte) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	user_json, _ := userlib.DatastoreGet(uuid) //retrieve the marshaled user info
	//just need to check integrity of user struct
	len_data := len(user_json) - userlib.HashSizeBytes
	just_user := user_json[:len_data] //remove HMAC for later use
	mac := user_json[len_data:]
	if len(just_user) < userlib.HashSizeBytes {
		//automatically return error, file has been changed
		return nil, errors.New("User data length has changed.")
	}

	//compute mac to set equal
	correct_mac, _ := userlib.HMACEval(hmac_key, just_user)
	if !userlib.HMACEqual(correct_mac, mac) {
		return nil, errors.New("User has been compromised.")
	}

	//if no errors, return user! depad, decrypt and then unmarshal
	userdata_padded := userlib.SymDec(decKey, just_user)
	userdata_final := PKCS(userdata_padded, "remove")

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
	updatedUser, err := GetLatestUser(userdata.UUID_, userdata.PasswordHash, userdata.HMACKey, userdata.EncKey)
	if err != nil {
		return errors.New("Failed to retrieve latest user info.")
	}
	//storing to revoked file does nothing, as long as it doesn't update the original file

	fileKey, exists := updatedUser.Filespace[filename]
	if !exists {
		//create new fileKey
		//creating the UUID for the FileKey
		storageKey := userlib.RandomBytes(16)
		fileKey.KeyId, _ = uuid.FromBytes(storageKey)

		enc_key, _ := userlib.HashKDF(storageKey, []byte("encryption"))
		fileKey.Enc_key = enc_key[:16]
		hmac_key, _ := userlib.HashKDF(storageKey, []byte("mac"))
		fileKey.HMAC_key = hmac_key[:16]
		fileKey.NumFiles = 1
		fileKey.SharedUsers = make(map[string][]string)
		fileKey.UserTokens = make(map[string]uuid.UUID)
		updatedUser.FilesOwned[filename] = fileKey
	} else { //overwrite file - shared users can overwrite this file
		//retrieve fileKey and delete any appended files from datastore if they exist

		//if this file was shared, retrieve fileKey through access token
		//access could have been revoked
		_, own := updatedUser.FilesOwned[filename]
		var thisFileKey FileKey
		if !own {
			at := userdata.AccessTokens[filename]
			thisFileKey, err = updatedUser.RetrieveAccessToken(at)
			if err != nil {
				return errors.New("Failed to retrieve access token.")
			}
		} else {
			currFileKey, _ := userlib.DatastoreGet(fileKey.KeyId)
			len_data := len(currFileKey) - userlib.HashSizeBytes

			if len_data < 0 || len_data > len(currFileKey) || len(currFileKey[:len_data]) < userlib.HashSizeBytes {
				//automatically return error, file has been changed
				return errors.New("FileKey data length has changed.")
			}
			//verify integrity of both fileKey struct and the file itself
			computedMac, _ := userlib.HMACEval(fileKey.HMAC_key, currFileKey[:len_data])
			if !userlib.HMACEqual(computedMac, currFileKey[len_data:]) {
				return errors.New("File key struct has been tampered with in Datastore.")
			}
			//decrypt + depad fileKey from DS to current fileKey var (overwrite)
			decrypt := userlib.SymDec(fileKey.Enc_key, currFileKey[:len_data])
			decrypt = PKCS(decrypt, "remove")

			err = json.Unmarshal(decrypt, &thisFileKey)
			if err != nil {
				return errors.New("Error demarshaling.")
			}
		}

		//delete appended files from key store
		for i := 1; i <= thisFileKey.NumFiles; i++ {
			//retrieve appropriate fileElem from Datastore, generate correct file ID
			keyMsg := thisFileKey.KeyId.String() + "_" + strconv.Itoa(i) //i is index of file
			key_bytes, _ := userlib.HMACEval(thisFileKey.HMAC_key, []byte(keyMsg))
			fileID, _ := uuid.FromBytes(key_bytes[:16])
			//deletes entry if it exists
			userlib.DatastoreDelete(fileID)
		}
		//generate new fileElem to send to datastore and update fileKey accordingly
		fileKey.KeyId = thisFileKey.KeyId
		fileKey.Enc_key = thisFileKey.Enc_key
		fileKey.HMAC_key = thisFileKey.HMAC_key
		fileKey.NumFiles = 1
		fileKey.SharedUsers = thisFileKey.SharedUsers
		fileKey.UserTokens = thisFileKey.UserTokens
	}
	//updates user's filespace, depending on share or not
	updatedUser.Filespace[filename] = fileKey
	fileElem.File_ind = 1
	//generates a new FileElem for overwrite as well
	key_msg := fileKey.KeyId.String() + "_" + strconv.Itoa(fileElem.File_ind)
	key_bytes, _ := userlib.HMACEval(fileKey.HMAC_key, []byte(key_msg))
	fileElem.FileID, _ = uuid.FromBytes(key_bytes[:16]) //new file ID based on file index and original fileKey
	fileElem.Filedata = data

	//now encrypt the FileKey, FileElem, and userData add HMACs, and send to datastore
	fk_marshal, _ := json.Marshal(fileKey)
	fe_marshal, _ := json.Marshal(fileElem)
	user_marshal, _ := json.Marshal(updatedUser)

	fk_IV := userlib.RandomBytes(userlib.AESBlockSizeBytes) //if IV isnt random, not secure
	fe_IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	user_IV := userlib.RandomBytes(userlib.AESBlockSizeBytes) //random IV each time

	enc_fileKey := userlib.SymEnc(fileKey.Enc_key, fk_IV, PKCS(fk_marshal, "add"))
	enc_fileElem := userlib.SymEnc(fileKey.Enc_key, fe_IV, PKCS(fe_marshal, "add"))
	enc_user := userlib.SymEnc(updatedUser.EncKey, user_IV, PKCS(user_marshal, "add"))
	fk_hmac, _ := userlib.HMACEval(fileKey.HMAC_key, enc_fileKey)
	fe_hmac, _ := userlib.HMACEval(fileKey.HMAC_key, enc_fileElem)
	user_hmac, _ := userlib.HMACEval(userdata.HMACKey, enc_user)

	enc_fileKey = append(enc_fileKey, fk_hmac...)
	enc_fileElem = append(enc_fileElem, fe_hmac...)
	enc_user = append(enc_user, user_hmac...)
	//Set can overwrite current data!
	userlib.DatastoreSet(fileKey.KeyId, enc_fileKey)
	userlib.DatastoreSet(fileElem.FileID, enc_fileElem)
	userlib.DatastoreSet(userdata.UUID_, enc_user)

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
//cant encrypt/decrypt entire file again, entire file doesnt need to be stored as one thing
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//if file DNE return error
	updatedUser, err := GetLatestUser(userdata.UUID_, userdata.PasswordHash, userdata.HMACKey, userdata.EncKey)
	if err != nil {
		return errors.New("Failed to retrieve latest user info.")
	}
	//again use access token if appending to shared file
	_, own := updatedUser.FilesOwned[filename]
	var fileKey FileKey
	if !own { //this is just in case a revocation has happened and the fileKey data has changed
		at := userdata.AccessTokens[filename]
		fileKey, err = updatedUser.RetrieveAccessToken(at)
		if err != nil {
			return errors.New("Failed to retrieve access token.")
		}
	} else { //but if you own the file, just directly retrieve fileKey
		fk, found := updatedUser.Filespace[filename]
		fileKeyDS, in_DS := userlib.DatastoreGet(fk.KeyId)

		if !found || !in_DS { //if file not in users file space or not found in Datastore, error
			return errors.New("File does not exist")
		}
		len_data := len(fileKeyDS) - userlib.HashSizeBytes //used for slicing out HMAC later

		if len(fileKeyDS[:len_data]) < userlib.HashSizeBytes {
			//automatically return error, file has been changed
			return errors.New("File key data length has changed.")
		}

		//need to check that the fileKey struct hasnt been corrupted, but not the last file
		//dont need to decrypt to do this
		computedMac, _ := userlib.HMACEval(fk.HMAC_key, fileKeyDS[:len_data])
		if !userlib.HMACEqual(computedMac, fileKeyDS[len_data:]) {
			return errors.New("File key has been tampered with in Datastore.")
		}

		//decrypt + depad fileKey from DS to current fileKey var (overwrite)
		decrypt := userlib.SymDec(fk.Enc_key, fileKeyDS[:len_data])
		decrypt = PKCS(decrypt, "remove")
		err = json.Unmarshal(decrypt, &fileKey)
		if err != nil {
			return errors.New("Error demarshaling.")
		}
	}

	//generate new file under same FileKey
	numFiles := fileKey.NumFiles
	file_ind := numFiles + 1
	fileKey.NumFiles = file_ind //increment number of files by 1

	keyMsg := fileKey.KeyId.String() + "_" + strconv.Itoa(file_ind)
	key_bytes, _ := userlib.HMACEval(fileKey.HMAC_key, []byte(keyMsg))
	fileID, _ := uuid.FromBytes(key_bytes[:16])

	//populate a new fileElem struct for the append
	fileElem := FileElem{fileID, data, file_ind}
	//question: does users Filespace get updated too automatically?

	//Marshal, pad, encrypt, append HMAC and send to Datastore (for updated FileKey and fileElem)
	fileElem_json, _ := json.Marshal(fileElem)
	fileKey_json, _ := json.Marshal(fileKey)

	fk_IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	fe_IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	fileElem_enc := userlib.SymEnc(fileKey.Enc_key, fe_IV, PKCS(fileElem_json, "add"))
	fileKey_enc := userlib.SymEnc(fileKey.Enc_key, fk_IV, PKCS(fileKey_json, "add"))

	//Add HMACs for both file key and file elem struct (runtime corresponds to size of appended file, nothing else)
	fk_hmac, _ := userlib.HMACEval(fileKey.HMAC_key, fileKey_enc)
	fe_hmac, _ := userlib.HMACEval(fileKey.HMAC_key, fileElem_enc)

	fileKey_enc = append(fileKey_enc, fk_hmac...)
	fileElem_enc = append(fileElem_enc, fe_hmac...)
	userlib.DatastoreSet(fileKey.KeyId, fileKey_enc)
	userlib.DatastoreSet(fileElem.FileID, fileElem_enc)

	return err
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	//TODO: This is a toy implementation.
	/*
		storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
		dataJSON, ok := userlib.DatastoreGet(storageKey)
		if !ok {
			return nil, errors.New(strings.ToTitle("File not found!"))
		}
		json.Unmarshal(dataJSON, &dataBytes)
	*/
	//if file DNE, return error. retrieve fileKey from Datastore
	updatedUser, err := GetLatestUser(userdata.UUID_, userdata.PasswordHash, userdata.HMACKey, userdata.EncKey)
	if err != nil {
		return nil, errors.New("Failed to retrieve latest user info.")
	}
	fileKey, found := updatedUser.Filespace[filename]

	if !found {
		return nil, errors.New("File not found in user's filespace.")
	}

	//again, check if ur loading shared file, if so retrieve through access token
	var latestFileKey FileKey
	_, own := updatedUser.FilesOwned[filename]
	if !own { //this is just in case a revocation has happened and the fileKey data has changed
		at := userdata.AccessTokens[filename]
		latestFileKey, err = updatedUser.RetrieveAccessToken(at)
		if err != nil {
			return nil, errors.New("Failed to retrieve access token.")
		}
	} else {
		fileKeyDS, found2 := userlib.DatastoreGet(fileKey.KeyId)
		if !found2 {
			return nil, errors.New("File not found in DataStore.")
		}

		len_data := len(fileKeyDS) - userlib.HashSizeBytes
		//fix ag panic
		if len_data < 0 || len_data > len(fileKeyDS) || len(fileKeyDS[:len_data]) < userlib.HashSizeBytes {
			//automatically return error, file has been changed
			return nil, errors.New("FileKey data length has changed.")
		}

		//verify integrity of both fileKey struct and the file itself
		computedMac, _ := userlib.HMACEval(fileKey.HMAC_key, fileKeyDS[:len_data])
		if !userlib.HMACEqual(computedMac, fileKeyDS[len_data:]) {
			return nil, errors.New("File key struct has been tampered with in Datastore.")
		}

		//decrypt fileKey in datastore to get latest version
		//decrypt > depad > unmarshal
		fileKey_pad := userlib.SymDec(fileKey.Enc_key, fileKeyDS[:len_data])
		fileKey_decrypt := PKCS(fileKey_pad, "remove")
		err = json.Unmarshal(fileKey_decrypt, &latestFileKey) //set current fileKey to latest
	}

	//now that we know fileKey is ok and we have the latest version,
	//check integrity of each file in file append
	var filePart []byte //this is the retrieved file elements DATA field

	for i := 1; i <= latestFileKey.NumFiles; i++ {
		//retrieve appropriate fileElem from Datastore, generate correct file ID
		keyMsg := latestFileKey.KeyId.String() + "_" + strconv.Itoa(i) //i is index of file
		key_bytes, _ := userlib.HMACEval(latestFileKey.HMAC_key, []byte(keyMsg))
		fileID, _ := uuid.FromBytes(key_bytes[:16])

		file_enc, err := userlib.DatastoreGet(fileID)
		len_file := len(file_enc) - userlib.HashSizeBytes

		if !err {
			error_msg := "File part not found: " + keyMsg
			return nil, errors.New(error_msg)
		}

		//fix ag out of bounds error
		if len_file < 0 || len_file > len(file_enc) || len(file_enc[:len_file]) < userlib.HashSizeBytes {
			//automatically return error, file has been changed
			return nil, errors.New("File data length has changed.")
		}

		//check integrity through HMAC
		fileMAC, _ := userlib.HMACEval(latestFileKey.HMAC_key, file_enc[:len_file])
		if !userlib.HMACEqual(fileMAC, file_enc[len_file:]) {
			error_msg := "File part has been compromised: " + keyMsg
			return nil, errors.New(error_msg)
		}

		//decrypt, depad, demarshal, and extract data field
		file_dec := userlib.SymDec(latestFileKey.Enc_key, file_enc[:len_file])
		file_dec = PKCS(file_dec, "remove")
		var file_demarsh FileElem
		err2 := json.Unmarshal(file_dec, &file_demarsh)

		if err2 != nil {
			error_msg := "Error unmarshaling this file part: " + keyMsg
			return nil, errors.New(error_msg)
		}

		//finally we have the unmarshaled file struct, set filePart to the data
		filePart = file_demarsh.Filedata
		dataBytes = append(dataBytes, filePart...)
	}

	return dataBytes, nil
}

//Helper struct for ShareFile. The record users send to DataStore when securely sharing a file
type ShareInvite struct {
	Sender     string //new field for when owner updates
	Signature  []byte
	RSAFileKey []byte
}

//Helper struct for Sharefile. Stores info necessary to get FileKey from datastore and decrypt
type FileKeyMeta struct {
	DSid    uuid.UUID
	HMACkey []byte
	ENCkey  []byte
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
//Return UUID storage key at which the secure file share invitation is stored in Datastore
//ERROR: given file does not exist in callers personal file space or
//sharing cannot complete due to malicious action
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {
	var shareInvite ShareInvite
	var fileKeyMeta FileKeyMeta
	//IMPLEMENT SHAREDUSERS AND USERTOKENS in FILEKEYSTRUCT

	//check is file exists in users file space
	updatedUser, err := GetLatestUser(userdata.UUID_, userdata.PasswordHash, userdata.HMACKey, userdata.EncKey)
	if err != nil {
		return uuid.Nil, errors.New("Failed to retrieve latest user info.")
	}

	var fk FileKey
	fileKey, fileFound := updatedUser.Filespace[filename]

	if !fileFound {
		return uuid.Nil, errors.New("File does not exist in caller's personal filespace.")
	}

	//what if this person is sharing a shared file? check access token!
	_, own := updatedUser.FilesOwned[filename]
	if !own { //this is just in case a revocation has happened and the fileKey data has changed
		at := userdata.AccessTokens[filename]
		fk, err = updatedUser.RetrieveAccessToken(at)
		if err != nil {
			return uuid.Nil, errors.New("Failed to retrieve access token.")
		}
	} else { //just in case fileKey data has changed from a recent session
		currFileKey, _ := userlib.DatastoreGet(fileKey.KeyId)
		len_data := len(currFileKey) - userlib.HashSizeBytes

		if len_data < 0 || len_data > len(currFileKey) || len(currFileKey[:len_data]) < userlib.HashSizeBytes {
			//automatically return error, file has been changed
			return uuid.Nil, errors.New("FileKey data length has changed.")
		}
		//verify integrity of both fileKey struct and the file itself
		computedMac, _ := userlib.HMACEval(fileKey.HMAC_key, currFileKey[:len_data])
		if !userlib.HMACEqual(computedMac, currFileKey[len_data:]) {
			return uuid.Nil, errors.New("File key struct has been tampered with in Datastore.")
		}
		//decrypt + depad fileKey from DS to current fileKey var (overwrite)
		decrypt := userlib.SymDec(fileKey.Enc_key, currFileKey[:len_data])
		decrypt = PKCS(decrypt, "remove")

		err = json.Unmarshal(decrypt, &fk)
		if err != nil {
			return uuid.Nil, errors.New("Error demarshaling.")
		}
	}

	//check if recipient exists
	pubKey, userFound := userlib.KeystoreGet(recipient + "public_key")
	if !userFound {
		return uuid.Nil, errors.New("Recepient not found.")
	}

	//populate Shareinvite and FileKeyMeta struct
	fileKeyMeta.DSid = fk.KeyId
	fileKeyMeta.HMACkey = fk.HMAC_key
	fileKeyMeta.ENCkey = fk.Enc_key

	fkm_json, _ := json.Marshal(fileKeyMeta)
	//encrypt FileKeyMeta using RSA
	fileKeyMeta_enc, _ := userlib.PKEEnc(pubKey, fkm_json) //dont need to pad?

	//Marshal the fileKeyMeta info
	shareInvite.RSAFileKey = fileKeyMeta_enc
	//msg for signature is the RSA encrypted, MARSHALED FileMetaKey struct
	shareInvite.Signature, _ = userlib.DSSign(userdata.PrivSignKey, shareInvite.RSAFileKey)
	shareInvite.Sender = updatedUser.Username
	shareInvite_json, _ := json.Marshal(shareInvite)

	accessToken = uuid.New() //generate random accessToken
	userlib.DatastoreSet(accessToken, shareInvite_json)

	//update SharedUsers and UserTokens fields in fileKey
	//if they are a DIRECT sharer (meaning theyre one level below owner) generate key
	//and put recipient in their list
	//else, put them under the direct sharer from their lineage
	fk.UserTokens[recipient] = accessToken                    //update user tokens for possible revoking later
	list, direct_user := fk.SharedUsers[updatedUser.Username] //should return true if user is a key
	if own {
		var emptyList []string
		fk.SharedUsers[recipient] = emptyList
	} else if direct_user {
		list = append(list, recipient) //add recipient to direct sharer's list
		fk.SharedUsers[recipient] = list
	} else { //indirect user case, iterate over map of shared users
		var originalSharer string
		//provides each key and respective value
		for directSharer, listShared := range fk.SharedUsers {
			for _, indirectSharer := range listShared {
				if updatedUser.Username == indirectSharer {
					originalSharer = directSharer
					break
				}
			}
			if originalSharer != "" {
				break //break out of second for loop if you've found the original sharer
			}
		}
		if originalSharer == "" {
			return uuid.Nil, errors.New("User is not owner but could not find who shared file with them.")
		}
		list = append(list, recipient)
		fk.SharedUsers[originalSharer] = list //add the recipient of this indirect user to list
	}
	//Now lets send the updated fileKey to the Datastore
	fileKey_json, _ := json.Marshal(fk)
	fk_IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	fileKey_enc := userlib.SymEnc(fk.Enc_key, fk_IV, PKCS(fileKey_json, "add"))
	//Add HMACs for both file key and file elem struct (runtime corresponds to size of appended file, nothing else)
	fk_hmac, _ := userlib.HMACEval(fk.HMAC_key, fileKey_enc)
	fileKey_enc = append(fileKey_enc, fk_hmac...)
	userlib.DatastoreSet(fileKey.KeyId, fileKey_enc)

	return accessToken, nil
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
//Adds a file that was shared w caller to personal namespace
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	//IMPLEMENT AccessTokens field IN USER STRUCT
	//even if revoked ok to not error, but bob cant see new file updates
	updatedUser, err := GetLatestUser(userdata.UUID_, userdata.PasswordHash, userdata.HMACKey, userdata.EncKey)
	if err != nil {
		return errors.New("Failed to retrieve latest user info.")
	}
	_, already_received := updatedUser.Filespace[filename]

	if already_received {
		return errors.New("File already in user's file space.")
	}

	sharedInviteDS, fileKeyFound := userlib.DatastoreGet(accessToken)

	if !fileKeyFound {
		return errors.New("Access token did not find a shared file.")
	}

	var sharedInvite ShareInvite
	err = json.Unmarshal(sharedInviteDS, &sharedInvite)

	if err != nil {
		return errors.New("Error unmarshaling shared file key.")
	}

	//now verify that sharedInvite has not been tampered with
	var senderKey userlib.PKEEncKey
	if sharedInvite.Sender == sender {
		senderKey, _ = userlib.KeystoreGet(sender + "ds")
	} else { //owner has updated ShareInvite
		senderKey, _ = userlib.KeystoreGet(sharedInvite.Sender + "ds")
	}
	//should check out if owner changes invite too
	err = userlib.DSVerify(senderKey, sharedInvite.RSAFileKey, sharedInvite.Signature)

	if err != nil {
		return errors.New("Failed to verify sender.")
	}

	//now we can finally receive the fileKey after unmarshaling
	//trying to decrypt marshaled RSAFileKey
	rsaFK_dec, err := userlib.PKEDec(userdata.PrivRSAKey, sharedInvite.RSAFileKey)
	if err != nil {
		return errors.New("Failed to decrypt FileKeyMeta info.")
	}

	var rsaFK FileKeyMeta
	err = json.Unmarshal(rsaFK_dec, &rsaFK)
	if err != nil {
		return errors.New("Error unmarshaling file key metadata.")
	}

	//now lets retrieve the fileKey from the datastore and append that to our users filespace
	fileKey, fkFound := userlib.DatastoreGet(rsaFK.DSid)

	if !fkFound {
		return errors.New("Could not find original file.")
	}

	//authenticate HMAC, decrypt, depad, demarshal fileKey and add to users filespace
	len_fk := len(fileKey) - userlib.HashSizeBytes
	if len(fileKey[:len_fk]) < userlib.HashSizeBytes {
		//automatically return error, file has been changed
		return errors.New("File key data length has changed.")
	}

	computedMac, _ := userlib.HMACEval(rsaFK.HMACkey, fileKey[:len_fk])
	if !userlib.HMACEqual(computedMac, fileKey[len_fk:]) {
		//should error if access revoked!
		return errors.New("File key struct has been tampered with in Datastore.")
	}
	//decrypt
	fileKey_dec := userlib.SymDec(rsaFK.ENCkey, fileKey[:len_fk])
	fileKey_dec = PKCS(fileKey_dec, "remove")
	var finalFK FileKey
	err = json.Unmarshal(fileKey_dec, &finalFK)

	if err != nil {
		return errors.New("Error unmarshaling actual file key.")
	}
	//generate a new fileKey for user! user can name file whatever they want

	//marshal, pad, encrypt, add HMAC and send userdata to DS
	userdata.Filespace[filename] = finalFK
	userdata.AccessTokens[filename] = accessToken
	user_json, _ := json.Marshal(userdata)
	user_IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	user_enc := userlib.SymEnc(userdata.EncKey, user_IV, PKCS(user_json, "add"))

	user_mac, _ := userlib.HMACEval(userdata.HMACKey, user_enc)
	user_enc = append(user_enc, user_mac...)
	userlib.DatastoreSet(userdata.UUID_, user_enc)

	return nil
}

//Helper function that retrieves fileKey at access token
//returns the datastore entry (still encrypted/MACed/marshaled)
func (userdata *User) RetrieveAccessToken(accessToken uuid.UUID) (fileKeyData FileKey, err error) {
	sharedInviteDS, fileKeyFound := userlib.DatastoreGet(accessToken)
	var fileKeyNil FileKey
	if !fileKeyFound {
		return fileKeyNil, errors.New("Access token did not find a shared file.")
	}

	var sharedInvite ShareInvite
	err = json.Unmarshal(sharedInviteDS, &sharedInvite)

	if err != nil {
		return fileKeyNil, errors.New("Error unmarshaling shared file key.")
	}

	//now verify that sharedInvite has not been tampered with
	var senderKey userlib.PKEEncKey
	senderKey, _ = userlib.KeystoreGet(sharedInvite.Sender + "ds")

	err = userlib.DSVerify(senderKey, sharedInvite.RSAFileKey, sharedInvite.Signature)

	if err != nil {
		return fileKeyNil, errors.New("Failed to verify sender.")
	}

	//now we can finally receive the fileKey after unmarshaling
	//trying to decrypt marshaled RSAFileKey
	rsaFK_dec, err := userlib.PKEDec(userdata.PrivRSAKey, sharedInvite.RSAFileKey)
	if err != nil {
		return fileKeyNil, errors.New("Failed to decrypt FileKeyMeta info.")
	}

	var rsaFK FileKeyMeta
	err = json.Unmarshal(rsaFK_dec, &rsaFK)
	if err != nil {
		return fileKeyNil, errors.New("Error unmarshaling file key metadata.")
	}

	//now lets retrieve the fileKey from the datastore and append that to our users filespace
	fileKey, fkFound := userlib.DatastoreGet(rsaFK.DSid)

	if !fkFound {
		return fileKeyNil, errors.New("couldn't find shared file key")
	}

	//authenticate HMAC, decrypt, depad, demarshal fileKey and add to users filespace
	len_fk := len(fileKey) - userlib.HashSizeBytes
	if len_fk < 0 || len_fk > len(fileKey) || len(fileKey[:len_fk]) < userlib.HashSizeBytes {
		//automatically return error, file has been changed
		return fileKeyNil, errors.New("File key data length has changed.")
	}

	computedMac, _ := userlib.HMACEval(rsaFK.HMACkey, fileKey[:len_fk])
	if !userlib.HMACEqual(computedMac, fileKey[len_fk:]) {
		return fileKeyNil, errors.New("File key struct has been tampered with in Datastore.")
	}
	//decrypt
	fileKey_dec := userlib.SymDec(rsaFK.ENCkey, fileKey[:len_fk])
	fileKey_dec = PKCS(fileKey_dec, "remove")
	err = json.Unmarshal(fileKey_dec, &fileKeyData)

	if err != nil {
		return fileKeyNil, errors.New("Error unmarshaling actual file key.")
	}

	return fileKeyData, nil
}

// RevokeFile is documented at: ONLY OWNER REVOKES
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
// Can only revoke access on users that they've DIRECTLY shared with
// should revoke even if recipient has not called ReceiveFile()
// revoked users cant take any ACTION on file - dont send any new access keys
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	//return error if not in personal filespace
	updatedUser, err := GetLatestUser(userdata.UUID_, userdata.PasswordHash, userdata.HMACKey, userdata.EncKey)
	if err != nil {
		return errors.New("Failed to retrieve latest user info.")
	}

	_, own := updatedUser.FilesOwned[filename]
	if !own {
		return errors.New("Cannot revoke file - user is not the owner.")
	}

	fileKey, in_filespace := updatedUser.Filespace[filename]
	if !in_filespace {
		return errors.New("File not in caller's personal namespace.")
	}
	//get current fileKey
	currFileKey, _ := userlib.DatastoreGet(fileKey.KeyId)
	len_data := len(currFileKey) - userlib.HashSizeBytes

	if len_data < 0 || len_data > len(currFileKey) || len(currFileKey[:len_data]) < userlib.HashSizeBytes {
		//automatically return error, file has been changed
		return errors.New("FileKey data length has changed.")
	}
	//verify integrity of both fileKey struct and the file itself
	computedMac, _ := userlib.HMACEval(fileKey.HMAC_key, currFileKey[:len_data])
	if !userlib.HMACEqual(computedMac, currFileKey[len_data:]) {
		return errors.New("File key struct has been tampered with in Datastore.")
	}
	//decrypt + depad fileKey from DS to current fileKey var (overwrite)
	decrypt := userlib.SymDec(fileKey.Enc_key, currFileKey[:len_data])
	decrypt = PKCS(decrypt, "remove")
	var fk FileKey
	err = json.Unmarshal(decrypt, &fk)
	if err != nil {
		return errors.New("Error demarshaling.")
	}

	//check if file is shared with target user
	revoked, shared := fk.SharedUsers[targetUsername]
	//userlib.DebugMsg("%v/n", fk.SharedUsers)
	if !shared {
		return errors.New("File not shared with target user")
	}
	old_enc := fk.Enc_key
	old_hmac := fk.HMAC_key

	//create new encryption keys, file key ID is the same though
	newKey := userlib.RandomBytes(16)
	enc_key, _ := userlib.HashKDF(newKey, []byte("encryption"))
	fk.Enc_key = enc_key[:16]
	hmac_key, _ := userlib.HashKDF(newKey, []byte("mac"))
	fk.HMAC_key = hmac_key[:16]

	//delete user tokens of those that have been revoked
	delete(fk.UserTokens, targetUsername) //get rid of targetUsers tokenfirst
	for _, user := range revoked {
		delete(fk.UserTokens, user)
	}
	//update SharedUsers
	delete(fk.SharedUsers, targetUsername) //deletes revoked user and associated users from SharedUsers

	//now iterate through non-revoked users and update accessTokens
	for directShared, indirectShared := range fk.SharedUsers {
		access_token, found := fk.UserTokens[directShared]
		if !found {
			return errors.New("Access token for direct user not found.")
		}
		userdata.updateAccessToken(access_token, fk.Enc_key, fk.HMAC_key, fk.KeyId, directShared)
		for _, restShared := range indirectShared {
			access_token, found2 := fk.UserTokens[restShared]
			if !found2 {
				return errors.New("Access token for indirect user not found.")
			}
			userdata.updateAccessToken(access_token, fk.Enc_key, fk.HMAC_key, fk.KeyId, restShared)
		}
	}
	//re encrypt all appended files
	for i := 1; i <= fk.NumFiles; i++ {
		//retrieve appropriate fileElem from Datastore, generate correct file ID
		keyMsg := fk.KeyId.String() + "_" + strconv.Itoa(i) //i is index of file
		key_bytes, _ := userlib.HMACEval(old_hmac, []byte(keyMsg))
		fileID, _ := uuid.FromBytes(key_bytes[:16])

		file_enc, err := userlib.DatastoreGet(fileID)
		len_file := len(file_enc) - userlib.HashSizeBytes

		if !err {
			error_msg := "File part not found: " + keyMsg
			return errors.New(error_msg)
		}

		//fix ag out of bounds error
		if len_file < 0 || len_file > len(file_enc) || len(file_enc[:len_file]) < userlib.HashSizeBytes {
			//automatically return error, file has been changed
			return errors.New("File data length has changed.")
		}

		//check integrity through HMAC
		fileMAC, _ := userlib.HMACEval(old_hmac, file_enc[:len_file])
		if !userlib.HMACEqual(fileMAC, file_enc[len_file:]) {
			error_msg := "File part has been compromised: " + keyMsg
			return errors.New(error_msg)
		}
		//DECRYPT
		file_dec := userlib.SymDec(old_enc, file_enc[:len_file])
		file_dec = PKCS(file_dec, "remove")
		var file_unmarsh FileElem
		error := json.Unmarshal(file_dec, &file_unmarsh)
		if error != nil {
			return errors.New("error unmarshaling file part")
		}

		key_bytesNew, _ := userlib.HMACEval(fk.HMAC_key, []byte(keyMsg))
		fileIDnew, _ := uuid.FromBytes(key_bytesNew[:16])
		file_unmarsh.FileID = fileIDnew
		file_marsh, _ := json.Marshal(file_unmarsh)

		//RE ENCRYPT WITH UPDATED KEYS, REMEMBER TO CHANGE FILE ID W NEW HMAC
		fe_IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
		enc_fileElem := userlib.SymEnc(fk.Enc_key, fe_IV, PKCS(file_marsh, "add"))
		fe_hmac, _ := userlib.HMACEval(fk.HMAC_key, enc_fileElem)

		enc_fileElem = append(enc_fileElem, fe_hmac...)
		userlib.DatastoreSet(file_unmarsh.FileID, enc_fileElem)
	}

	//encrypt filekey again and send to datastore
	fileKey_json, _ := json.Marshal(fk)
	fk_IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	//using new encryption key
	fileKey_enc := userlib.SymEnc(fk.Enc_key, fk_IV, PKCS(fileKey_json, "add"))
	//Add HMACs for both file key and file elem struct (runtime corresponds to size of appended file, nothing else)
	fk_hmac, _ := userlib.HMACEval(fk.HMAC_key, fileKey_enc)
	fileKey_enc = append(fileKey_enc, fk_hmac...)
	userlib.DatastoreSet(fk.KeyId, fileKey_enc)

	//encrypt updated userdata and send to datastore
	updatedUser.FilesOwned[filename] = fk
	updatedUser.Filespace[filename] = fk
	user_marshal, _ := json.Marshal(updatedUser)
	user_IV := userlib.RandomBytes(userlib.AESBlockSizeBytes) //random IV each time
	enc_user := userlib.SymEnc(updatedUser.EncKey, user_IV, PKCS(user_marshal, "add"))
	user_hmac, _ := userlib.HMACEval(updatedUser.HMACKey, enc_user)
	enc_user = append(enc_user, user_hmac...)
	userlib.DatastoreSet(userdata.UUID_, enc_user)

	return
}

//helper function to update access tokens during revocation for non-revoked users
func (userdata *User) updateAccessToken(accessToken uuid.UUID, enc_key []byte, hmac_key []byte, fk_id uuid.UUID, recipient string) error {
	sharedInviteDS, fileKeyFound := userlib.DatastoreGet(accessToken)

	if !fileKeyFound {
		return errors.New("Access token did not find a shared file.")
	}

	var sharedInvite ShareInvite
	err := json.Unmarshal(sharedInviteDS, &sharedInvite)

	if err != nil {
		return errors.New("Error unmarshaling shared file key.")
	}

	//now verify that sharedInvite has not been tampered with
	var senderKey userlib.PKEEncKey
	senderKey, _ = userlib.KeystoreGet(sharedInvite.Sender + "ds")

	err = userlib.DSVerify(senderKey, sharedInvite.RSAFileKey, sharedInvite.Signature)

	if err != nil {
		return errors.New("Shared invite has been tampered with.")
	}
	var fileKeyMeta FileKeyMeta
	var shareInvite ShareInvite

	//NOW, UPDATE
	//populate Shareinvite and FileKeyMeta struct
	fileKeyMeta.DSid = fk_id
	fileKeyMeta.HMACkey = hmac_key
	fileKeyMeta.ENCkey = enc_key

	fkm_json, _ := json.Marshal(fileKeyMeta)
	//encrypt FileKeyMeta using RSA
	pubKey, userFound := userlib.KeystoreGet(recipient + "public_key")
	if !userFound {
		return errors.New("Recepient not found.")
	}
	fileKeyMeta_enc, _ := userlib.PKEEnc(pubKey, fkm_json) //dont need to pad?

	//Marshal the fileKeyMeta info
	shareInvite.RSAFileKey = fileKeyMeta_enc
	//msg for signature is the RSA encrypted, MARSHALED FileMetaKey struct
	shareInvite.Signature, _ = userlib.DSSign(userdata.PrivSignKey, shareInvite.RSAFileKey)
	shareInvite.Sender = userdata.Username //should be owners username now
	shareInvite_json, _ := json.Marshal(shareInvite)

	userlib.DatastoreSet(accessToken, shareInvite_json)
	return nil
}
