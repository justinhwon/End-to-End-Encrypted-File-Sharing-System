package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
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

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username     string
	Password     string
	FileToUUID   map[string]uuid.UUID
	FileToFileEK map[string][]byte
	PDecKey      userlib.PKEDecKey
	SignKey      userlib.DSSignKey
	UserUUID     uuid.UUID

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {

	// Generate Public Key Encryption Keys
	ek, dk, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	// Generate Digital Signature Keys
	sk, vk, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	// Publish the public keys to the keystore
	err = userlib.KeystoreSet(username+"PubEncKey", ek)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"DSVerKey", vk)
	if err != nil {
		return nil, err
	}

	// Generate a key used to create a uuid to store the user data.
	// Also used to encrypt the user data.
	basekey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	userhash, err := userlib.HMACEval(basekey, []byte("randomstring"))
	if err != nil {
		return nil, err
	}
	useruuid, _ := uuid.FromBytes(userhash[:16])

	// Initialize a User structure
	userdata := User{
		username,
		password,
		make(map[string]uuid.UUID),
		make(map[string][]byte),
		dk,
		sk,
		useruuid,
	}

	// A byte array representaion of the user data.
	userdatajson, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	encuserdata, tag, err := AuthEnc(basekey, userdatajson)
	if err != nil {
		return nil, err
	}
	encuserdata = append(tag, encuserdata...)
	userlib.DatastoreSet(useruuid, encuserdata)

	userdataptr = &userdata
	return &userdata, nil
}

// This fetches the user information from the Datastore. It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	// Generate a key used to create a uuid to retrieve the user data.
	// Also used to decrypt the user data.
	basekey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	userhash, err := userlib.HMACEval(basekey, []byte("randomstring"))
	if err != nil {
		return nil, err
	}
	useruuid, _ := uuid.FromBytes(userhash[:16])

	// Retrieve encrypted user data from the datastore.
	encuserdata, ok := userlib.DatastoreGet(useruuid)
	if !ok {
		return nil, errors.New("user with given username and password does not exist")
	}

	// Decrypt userdata
	userdatajson, err := AuthDec(basekey, encuserdata)
	if err != nil {
		return nil, err
	}

	// Converts json format of user data into User struct
	var userdata User
	json.Unmarshal(userdatajson, &userdata)
	userdataptr = &userdata

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	fileenckey := userlib.RandomBytes(16)
	uuidlist := SliceAndStore(0, fileenckey, data)

	// The uuid of the list of uuid's. Used to store the list in the datastore
	listuuid := uuid.New()
	uuidlistjson, _ := json.Marshal(uuidlist)
	encuuidlist, tag, _ := AuthEnc(fileenckey, uuidlistjson)
	encuuidlist = append(tag, encuuidlist...)
	userlib.DatastoreSet(listuuid, encuuidlist)

	userdata.FileToUUID[filename] = listuuid
	userdata.FileToFileEK[filename] = fileenckey

	// A byte array representaion of the user data.
	userdatajson, _ := json.Marshal(*userdata)
	basekey :=
		userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	encuserdata, tag, _ := AuthEnc(basekey, userdatajson)

	encuserdata = append(tag, encuserdata...)
	userlib.DatastoreSet(userdata.UserUUID, encuserdata)
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	listuuid, ok := userdata.FileToUUID[filename]
	// Check if file actually exists
	if !ok {
		return errors.New("file " + filename + " does not exist")
	}
	fileenckey, _ := userdata.FileToFileEK[filename]

	// Retrieve encrypted list of uuids
	encuuidlist, ok := userlib.DatastoreGet(listuuid)
	if !ok {
		return errors.New("something went wrong while retrieving the file")
	}
	uuidlistjson, err := AuthDec(fileenckey, encuuidlist)
	if err != nil {
		return err
	}

	// Parse json as list of uuid's
	var uuidlist []uuid.UUID
	json.Unmarshal(uuidlistjson, &uuidlist)
	// Retrieve the last file slice
	lastsliceuuid := uuidlist[len(uuidlist)-1]
	lastencslice, ok := userlib.DatastoreGet(lastsliceuuid)
	if !ok {
		return errors.New("something went wrong while retrieving the file")
	}

	lastslice, err := AuthDec(fileenckey, lastencslice)
	if err != nil {
		return err
	}

	// Append the data to the last slice of the existing data
	newdata := append(lastslice, data...)

	// Encrypt and store the first 64 bytes of the new data
	var fileslice []byte
	if 64 > len(newdata) {
		fileslice = newdata[:]
	} else {
		fileslice = newdata[:64]
	}
	encfileslice, tag, _ := AuthEnc(fileenckey, fileslice)
	encfileslice = append(tag, encfileslice...)
	userlib.DatastoreSet(lastsliceuuid, encfileslice)

	// Store the new uuid's of the file slices
	var newuuidlist []uuid.UUID
	if 64 <= len(newdata) {
		newuuidlist := SliceAndStore(64, fileenckey, newdata)
	}

	// Store the updated list of uuids in the datastore
	uuidlist = append(uuidlist, newuuidlist...)
	uuidlistjson, _ = json.Marshal(uuidlist)
	encuuidlist, tag, _ = AuthEnc(fileenckey, uuidlistjson)
	encuuidlist = append(tag, encuuidlist...)
	userlib.DatastoreSet(listuuid, encuuidlist)
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	listuuid, ok := userdata.FileToUUID[filename]
	// Check if file actually exists
	if !ok {
		return nil, errors.New("file " + filename + " does not exist")
	}
	fileenckey, _ := userdata.FileToFileEK[filename]

	// Retrieve encrypted list of uuids
	encuuidlist, ok := userlib.DatastoreGet(listuuid)
	if !ok {
		return nil, errors.New("something went wrong while retrieving the file")
	}
	uuidlistjson, err := AuthDec(fileenckey, encuuidlist)
	if err != nil {
		return nil, err
	}
	var uuidlist []uuid.UUID
	json.Unmarshal(uuidlistjson, &uuidlist)

	// Iterate through each file slice in the datastore and piece them back together
	for _, sliceuuid := range uuidlist {
		encfileslice, ok := userlib.DatastoreGet(sliceuuid)
		if !ok {
			return nil, errors.New("something went wrong while retrieving the file")
		}
		fileslice, err := AuthDec(fileenckey, encfileslice)
		if err != nil {
			return nil, err
		}
		data = append(data, fileslice...)
	}

	return data, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	//magicKey holds (FileEnc Key, UUID to LL) -> (16bytes, 16 bytes)
	uuidToList, ok := FileToUUID[filename]
	// error if key does not exist
	if ok == false {
		return err
	}
	fileEncKey, ok := FileToFileEK[filename]
	// error if key does not exist
	if ok == false {
		return err
	}
	uuidBytes, err := json.Marshal(uuidToList)
	if err != nil {
		return nil, err
	}
	magicKey = append(fileEncKey, uuidBytes...)

	// get public key of recipient
	recipientPk, ok := userlib.KeystoreGet(recipient+"PubEncKey")
	// error if key does not exist
	if ok == false {
		return nil, err
	}

	// encrypt magicKey using PKE with recipient's pk
	encMagicKey, err := userlib.PKEEnc(recipientPk, magicKey)
	if err != nil {
		return nil, err
	}

	// create a digital signature Sig for encMagicKey using owner's signing key
	sig, err := userlib.DSSign(userdata.SignKey, encMagicKey)
	if err != nil {
		return nil, err
	}

	// [256 bytes sig, encMagicKey]
	magic_string = append(sig, encMagicKey...)
	

	return magic_string, nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {

	// Get verification key of sender
	senderVk, ok := userlib.KeystoreGet(recipient+"DSVerKey")
	// error if key does not exist
	if ok == false {
		return err
	}

	// Obtain sig and encMagicKey from magic_string
	sig := magic_string[0:256]
	encMagicKey := magic_string[256:]

	// Verify authenticy and integrity using digital signature
	err := DSVerify(senderVk, magic_string, sig)
	if err != nil {
		return err
	}

	// Decrypt encMagicKey using receiver's private key
	magicKey, err := PKEDec(userdata.PDecKey, encMagicKey)
	if err != nil {
		return err
	}

	// Separate magicKey into UUID and FileEnc Key
	fileEncKey := magicKey[0:16]
	uuidToListjson := magicKey[16:]

	// Convert uuidToLLjson back into uuid type
	var uuidToList uuid.UUID
	json.Unmarshal(uuidToListjson, &uuidToList)

	// Check if filename already exists, if yes then error
	test, ok := userdata.FileToUUID[filename]
	if ok == true {
		return err
	}

	//Otherwise add to hashmap so recipient can access file
	userdata.FileToUUID[filename] = uuidToList
	userdata.FileToFileEK = fileEncKey

	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {

	//get uuid and filenckey
	uuidToList, ok := FileToUUID[filename]
	// error if key does not exist
	if ok == false {
		return err
	}
	fileEncKey, ok := FileToFileEK[filename]
	// error if key does not exist
	if ok == false {
		return err
	}

	// retrieve encrypted list of uuids
	encUuidList, ok := userlib.DatastoreGet(uuidToList)
	if !ok {
		return errors.New("something went wrong while retrieving the file")
	}

	//upload this encrypted list somewhere else in datastore in random UUID
	newListUuid := uuid.New()
	userlib.DatastoreSet(newListUuid, encUuidList)
	//update the uuidToList value
	FileToUUID[filename] = newListUuid

	//delete the current value in datastore
	userlib.DatastoreDelete(uuidToList)

	return nil
}

// An authenticated encryption scheme using HMAC, HKDF and symmetric encryption
func AuthEnc(key []byte, data []byte) (encdata []byte, tag []byte, err error) {
	// Create symmetric key for symmetric encryption
	symmkey, err := userlib.HMACEval(key, []byte("randomstring1"))
	if err != nil {
		return nil, nil, err
	}
	// Create HMAC key used to create tag for HMAC
	hmackey, err := userlib.HMACEval(key, []byte("randomstring2"))
	if err != nil {
		return nil, nil, err
	}
	encdata = userlib.SymEnc(symmkey, userlib.RandomBytes(16), data)
	tag, err = userlib.HMACEval(hmackey, encdata)

	return encdata, tag, err
}

// An authenticated decryption scheme using HMAC, HKDF, and symmetric decryption
func AuthDec(key []byte, encdata []byte) (data []byte, err error) {
	// Create symmetric key for symmetric encryption
	symmkey, err := userlib.HMACEval(key, []byte("randomstring1"))
	if err != nil {
		return nil, err
	}
	// Create HMAC key used to create tag for HMAC
	hmackey, err := userlib.HMACEval(key, []byte("randomstring2"))
	if err != nil {
		return nil, err
	}
	// The tag given as part of the encrypted data
	giventag, encdata := encdata[:16], encdata[16:]

	expectedtag, err := userlib.HMACEval(hmackey, encdata)
	if err != nil {
		return nil, err
	}
	// Authenticate and check the integrity of the data
	if !userlib.HMACEqual(expectedtag, giventag) {
		return nil, errors.New("the data could not be authenticated and its integrity could not be verified")
	}
	data = userlib.SymDec(symmkey, encdata)
	return data, nil
}

func SliceAndStore(start int, key []byte, data []byte) (uuidlist []uuid.UUID) {
	for i := start; i < len(data); i += 64 {
		fileuuid := uuid.New()
		uuidlist = append(uuidlist, fileuuid)

		var fileslice []byte
		if i+64 > len(data) {
			fileslice = data[i:]
		} else {
			fileslice = data[i : i+64]
		}
		encfileslice, tag, _ := AuthEnc(key, fileslice)
		encfileslice = append(tag, encfileslice...)
		userlib.DatastoreSet(fileuuid, encfileslice)
	}
	return uuidlist
}
