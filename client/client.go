package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/hex"
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username   string
	SK         []byte
	PrivateKey userlib.PKEDecKey
	PublicKey  userlib.PKEEncKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// EncryptedBlob definition
type EncryptedBlob struct {
	IV         []byte
	Ciphertext []byte
	MAC        []byte
}

type UserObject struct {
	SaltUUID       uuid.UUID
	PrivateKeyUUID uuid.UUID
}

type FileObject struct {
	Head  uuid.UUID
	Tail  uuid.UUID
	Key   []byte
	Tree  uuid.UUID
	Owner string
}

type FileContent struct {
	Content []byte
	Next    uuid.UUID
}

type Invitation struct {
	FileUUID uuid.UUID // Pointer to shared file
	FileKey  []byte    // Symmetric key to decrypt FileObject and contents
	FromUser string    // Who shared it
}

// Helper Functions

func Enc_then_mac_hash(K []byte, IV []byte, plaintext []byte) (EncryptedBlob, error) {
	KDFOutput, err := userlib.HashKDF(K, []byte("key one"))
	if err != nil {
		return EncryptedBlob{}, err
	}
	K1 := KDFOutput[:16]
	K2 := KDFOutput[16:32]

	ciphertext := userlib.SymEnc(K1, IV, plaintext)
	macInput := append(append([]byte{}, IV...), ciphertext...)
	mac, err := userlib.HMACEval(K2, macInput)
	if err != nil {
		return EncryptedBlob{}, err
	}

	return EncryptedBlob{IV: IV, Ciphertext: ciphertext, MAC: mac}, nil
}

func Mac_hash_then_decrypt(K []byte, blob EncryptedBlob) (plaintext []byte, err error) {
	// Validate blob
	if len(blob.IV) != 16 {
		return nil, errors.New("invalid IV length")
	}
	if len(blob.Ciphertext) == 0 || len(blob.MAC) == 0 {
		return nil, errors.New("invalid blob: missing fields")
	}

	// Derive K1 (encryption) and K2 (MAC) from K
	KDFOutput, err := userlib.HashKDF(K, []byte("key one"))
	if err != nil {
		return nil, err
	}
	if len(KDFOutput) < 32 {
		return nil, errors.New("insufficient KDF output length")
	}
	K1 := KDFOutput[:16]
	K2 := KDFOutput[16:32]

	// Verify MAC = HMAC(K2, IV || ciphertext)
	macInput := append(append([]byte{}, blob.IV...), blob.Ciphertext...)
	expectedMAC, err := userlib.HMACEval(K2, macInput)
	if err != nil {
		return nil, err
	}

	if !userlib.HMACEqual(expectedMAC, blob.MAC) {
		return nil, errors.New("integrity check failed: MAC mismatch")
	}

	// Decrypt and return plaintext
	plaintext = userlib.SymDec(K1, blob.Ciphertext)
	return plaintext, nil
}

func slow_hash(pw []byte, salt []byte) (encryptedMessage []byte, e error) {
	// Salt length check
	if len(salt) != 16 {
		return nil, errors.New("invalid Salt length")
	}
	return userlib.Argon2Key(pw, salt, 16), nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	// Check length username nonzero
	if len(username) == 0 {
		return nil, errors.New("InitUser: username cannot be empty")
	}

	// Map username to determinitstic uuid
	userUUID, e := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if e != nil {
		return nil, errors.New("InitUser: failed to derive user UUID from username")
	}

	// Make sure username doesn't exist yet
	if _, exists := userlib.DatastoreGet(userUUID); exists {
		return nil, fmt.Errorf("InitUser: username %q already exists", username)
	}

	// generate UUIDs for location of salt, privateKey and userObject
	saltUUID := uuid.New()
	privateKeyUUID := uuid.New()
	userObjectIV := uuid.New()

	// userObject points to salt and privateKey pointers
	userObject := UserObject{
		SaltUUID:       saltUUID,
		PrivateKeyUUID: privateKeyUUID,
	}

	userObjectBytes, err := json.Marshal(userObject)
	if err != nil {
		return nil, errors.New("InitUser: error while Marshal userObject")
	}

	// derive key K from password. HashKDF K and split into k1 and k2
	K := userlib.Hash([]byte(password))

	KDFOutput, err := userlib.HashKDF(K[:16], []byte("key one"))
	if err != nil {
		return nil, errors.New("InitUser: key derivation failed")
	}
	if len(KDFOutput) < 32 {
		return nil, errors.New("InitUser: insufficient KDF output length")
	}
	K1 := KDFOutput[:16]   // root key for userObject blob
	K2 := KDFOutput[16:32] // root key for salt blob

	// encrypt userObject with K1 and store under userUUID
	encUserBlob, err := Enc_then_mac_hash(K1, userObjectIV[:], userObjectBytes)
	if err != nil {
		return nil, err
	}

	encUserBytes, err := json.Marshal(encUserBlob)
	if err != nil {
		return nil, errors.New("InitUser: error while marshaling encrypted user object")
	}

	userlib.DatastoreSet(userUUID, encUserBytes)

	// generate salt, encrypt it with K2, and store under saltUUID
	salt := uuid.New()
	saltIV := uuid.New() // IV for salt

	encSaltBlob, err := Enc_then_mac_hash(K2, saltIV[:], salt[:16])
	if err != nil {
		return nil, err
	}

	encSaltBytes, err := json.Marshal(encSaltBlob)
	if err != nil {
		return nil, errors.New("InitUser: error while marshaling encrypted salt")
	}

	userlib.DatastoreSet(saltUUID, encSaltBytes)

	// Slow hash SK from password and salt
	SK, err := slow_hash([]byte(password), salt[:16])
	if err != nil {
		return nil, err
	}

	// generate keypair and put public key in Keystore username -> key
	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	userlib.KeystoreSet(username, publicKey)

	// Encrypt private key with SK and store under privateKeyUUID
	privateKeyIV := uuid.New()

	// key to bytes before encryption
	privBytes, err := json.Marshal(privateKey)
	if err != nil {
		return nil, errors.New("InitUser: failed to marshal private key")
	}

	encPrivBlob, err := Enc_then_mac_hash(SK, privateKeyIV[:], privBytes)
	if err != nil {
		return nil, errors.New("InitUser: failed to encrypt then MAC private key")
	}

	encPrivBytes, err := json.Marshal(encPrivBlob)
	if err != nil {
		return nil, errors.New("InitUser: failed to marshal encrypted private key")
	}

	userlib.DatastoreSet(privateKeyUUID, encPrivBytes)

	// Construct local user struct
	user := &User{
		Username:   username,
		SK:         SK,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}

	return user, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// Check length username nonzero
	if len(username) == 0 {
		return nil, errors.New("GetUser: username cannot be empty")
	}

	// Compute deterministic UUID for username
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, errors.New("GetUser: failed to compute UUID for username")
	}

	// Make sure username exists
	data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("GetUser: user does not exist in datastore")
	}

	// Derive key K
	K := userlib.Hash([]byte(password))
	KDF_output, err := userlib.HashKDF(K[:16], []byte("key one"))
	if err != nil {
		return nil, errors.New("GetUser: HashKDF failed for password")
	}
	if len(KDF_output) < 32 {
		return nil, errors.New("GetUser: insufficient KDF output length")
	}
	K1 := KDF_output[:16]
	K2 := KDF_output[16:32]

	// Unmarshal and decrypt user metadata
	var userRecord EncryptedBlob
	if err := json.Unmarshal(data, &userRecord); err != nil {
		return nil, errors.New("GetUser: failed to unmarshal user record blob")
	}

	decryptedUserStruct, err := Mac_hash_then_decrypt(K1, userRecord)
	if err != nil {
		return nil, errors.New("GetUser: user struct MAC check failed or password incorrect")
	}

	var userStruct UserObject
	if err := json.Unmarshal(decryptedUserStruct, &userStruct); err != nil {
		return nil, errors.New("GetUser: malformed user metadata after decryption")
	}

	// Load and decrypt salt
	saltBlobBytes, ok := userlib.DatastoreGet(userStruct.SaltUUID)
	if !ok {
		return nil, errors.New("GetUser: salt not found in datastore")
	}

	var saltBlob EncryptedBlob
	if err := json.Unmarshal(saltBlobBytes, &saltBlob); err != nil {
		return nil, errors.New("GetUser: malformed salt encrypted blob")
	}

	saltBytes, err := Mac_hash_then_decrypt(K2, saltBlob)
	if err != nil {
		return nil, errors.New("GetUser: salt MAC check failed or password incorrect")
	}

	// Slow hash to derive SK
	SK, err := slow_hash([]byte(password), saltBytes)
	if err != nil {
		return nil, errors.New("GetUser: slow_hash failed")
	}

	// Load and decrypt private key
	privateKeyBlobBytes, ok := userlib.DatastoreGet(userStruct.PrivateKeyUUID)
	if !ok {
		return nil, errors.New("GetUser: private key not found in datastore")
	}

	var privateKeyBlob EncryptedBlob
	if err := json.Unmarshal(privateKeyBlobBytes, &privateKeyBlob); err != nil {
		return nil, errors.New("GetUser: malformed encrypted private key blob")
	}

	privateKeyBytes, err := Mac_hash_then_decrypt(SK, privateKeyBlob)
	if err != nil {
		return nil, errors.New("GetUser: private key MAC check failed or password incorrect")
	}

	var privateKey userlib.PKEDecKey
	if err := json.Unmarshal(privateKeyBytes, &privateKey); err != nil {
		return nil, errors.New("GetUser: private key could not be unmarshaled")
	}

	// Load public key from keystore
	publicKey, ok := userlib.KeystoreGet(username)
	if !ok {
		return nil, errors.New("GetUser: public key not found in keystore")
	}

	// Construct and return user struct
	returnUser := &User{
		Username:   username,
		SK:         SK,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
	return returnUser, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Derive deterministic UUID for this user’s encrypted file map
	mapUUIDBytes := userlib.Hash([]byte("filemap" + hex.EncodeToString(userdata.SK)))[:16]
	mapUUID, err := uuid.FromBytes(mapUUIDBytes)
	if err != nil {
		return err
	}

	// Load or initialize file map
	data, exists := userlib.DatastoreGet(mapUUID)
	var fileMap map[string]uuid.UUID
	if exists {
		var encMapBlob EncryptedBlob
		if err = json.Unmarshal(data, &encMapBlob); err != nil {
			return errors.New("StoreFile: unmarshal map failed")
		}
		mapBytes, err := Mac_hash_then_decrypt(userdata.SK, encMapBlob)
		if err != nil {
			return errors.New("StoreFile: map integrity check failed")
		}
		if err = json.Unmarshal(mapBytes, &fileMap); err != nil {
			return errors.New("StoreFile: unmarshal map failed")
		}
	} else {
		fileMap = make(map[string]uuid.UUID)
	}

	// Generate random key for this file
	fileKey := userlib.RandomBytes(16)

	// Create first content node
	headUUID := uuid.New()
	fileContent := FileContent{
		Content: content,
		Next:    uuid.Nil,
	}

	nodeBytes, err := json.Marshal(fileContent)
	if err != nil {
		return fmt.Errorf("StoreFile: failed to marshal content node: %v", err)
	}
	IV1 := userlib.RandomBytes(16)
	encNode, err := Enc_then_mac_hash(fileKey, IV1, nodeBytes)
	if err != nil {
		return fmt.Errorf("StoreFile: failed to encrypt node: %v", err)
	}
	encNodeBytes, err := json.Marshal(encNode)
	if err != nil {
		return fmt.Errorf("failed to marshal node encryption: %v", err)
	}

	userlib.DatastoreSet(headUUID, encNodeBytes)

	// Create FileObject with Head, Tail, Key, and placeholder Tree
	fileObj := FileObject{
		Head: headUUID,
		Tail: headUUID,
		Key:  fileKey,
		Tree: uuid.Nil, // placeholder for ownership tree
	}
	fileObj.Owner = userdata.Username

	fileUUID := uuid.New()
	objBytes, err := json.Marshal(fileObj)
	if err != nil {
		return fmt.Errorf("StoreFile: failed to marshal FileObject: %v", err)
	}
	IV2 := userlib.RandomBytes(16)
	encObj, err := Enc_then_mac_hash(fileObj.Key, IV2, objBytes)

	if err != nil {
		return fmt.Errorf("StoreFile: failed to encrypt FileObject: %v", err)
	}
	encObjBytes, _ := json.Marshal(encObj)
	userlib.DatastoreSet(fileUUID, encObjBytes)

	// Store encrypted copy of fileKey under deterministic UUID
	keyUUIDBytes := userlib.Hash([]byte("filekey_" + filename + hex.EncodeToString(userdata.SK)))[:16]
	keyUUID, _ := uuid.FromBytes(keyUUIDBytes)

	encFileKey, err := Enc_then_mac_hash(userdata.SK, userlib.RandomBytes(16), fileKey)
	if err != nil {
		return fmt.Errorf("StoreFile: failed to encrypt file key: %v", err)
	}
	encFileKeyBytes, err := json.Marshal(encFileKey)
	if err != nil {
		return fmt.Errorf("StoreFile: failed to marshal encrypted file key: %v", err)
	}

	userlib.DatastoreSet(keyUUID, encFileKeyBytes)

	// Add entry in file map
	fileMap[filename] = fileUUID

	// Re-encrypt and save file map
	mapBytes, err := json.Marshal(fileMap)
	if err != nil {
		return fmt.Errorf("StoreFile: marshal map failed: %v", err)
	}
	IV3 := userlib.RandomBytes(16)
	blob, err := Enc_then_mac_hash(userdata.SK, IV3, mapBytes)
	if err != nil {
		return fmt.Errorf("StoreFile: encrypt map failed: %v", err)
	}
	blobBytes, _ := json.Marshal(blob)
	userlib.DatastoreSet(mapUUID, blobBytes)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	// Derive deterministic UUID for this user’s encrypted file map
	mapUUIDBytes := userlib.Hash([]byte("filemap" + hex.EncodeToString(userdata.SK)))[:16]
	mapUUID, err := uuid.FromBytes(mapUUIDBytes)
	if err != nil {
		return err
	}

	// Retrieve and decrypt user’s file map
	mapData, ok := userlib.DatastoreGet(mapUUID)
	if !ok {
		return errors.New("AppendToFile: file map not found")
	}
	var encMapBlob EncryptedBlob
	if err = json.Unmarshal(mapData, &encMapBlob); err != nil {
		return errors.New("AppendToFile: failed to unmarshal map")
	}
	mapBytes, err := Mac_hash_then_decrypt(userdata.SK, encMapBlob)
	if err != nil {
		return errors.New("AppendToFile: map integrity check failed")
	}
	var fileMap map[string]uuid.UUID
	if err = json.Unmarshal(mapBytes, &fileMap); err != nil {
		return errors.New("AppendToFile: failed to unmarshal map")
	}

	// Look up target file
	fileUUID, exists := fileMap[filename]
	if !exists {
		return errors.New("AppendToFile: file not found")
	}

	// Fetch and decrypt file object (contains head, tail, key, etc.)
	fileObjBytes, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return errors.New("AppendToFile: missing file metadata")
	}
	var encFileObj EncryptedBlob
	if err = json.Unmarshal(fileObjBytes, &encFileObj); err != nil {
		return errors.New("AppendToFile: failed to unmarshal file object blob")
	}
	// Retrieve file key from keyUUID
	keyUUIDBytes := userlib.Hash([]byte("filekey_" + filename + hex.EncodeToString(userdata.SK)))[:16]
	keyUUID, _ := uuid.FromBytes(keyUUIDBytes)
	encFileKeyBytes, ok := userlib.DatastoreGet(keyUUID)
	if !ok {
		return errors.New("AppendToFile: file key not found")
	}

	var encFileKey EncryptedBlob
	if err = json.Unmarshal(encFileKeyBytes, &encFileKey); err != nil {
		return errors.New("AppendToFile: failed to unmarshal file key blob")
	}
	fileKey, err := Mac_hash_then_decrypt(userdata.SK, encFileKey)
	if err != nil {
		return errors.New("AppendToFile: file key integrity check failed")
	}

	// use fileKey instead of SK
	fileObjPlain, err := Mac_hash_then_decrypt(fileKey, encFileObj)
	if err != nil {
		return errors.New("AppendToFile: file metadata integrity check failed")
	}
	var fileObj FileObject
	if err = json.Unmarshal(fileObjPlain, &fileObj); err != nil {
		return errors.New("AppendToFile: failed to unmarshal FileObject")
	}

	// Create new content node for appended data
	var fileContent FileContent
	fileContent.Content = content
	fileContent.Next = uuid.Nil
	fileContentUUID := uuid.New()

	// Encrypt and store new node
	IV1 := userlib.RandomBytes(16)
	fileContentBlobBytes, err := json.Marshal(fileContent)
	if err != nil {
		return fmt.Errorf("marshal file blob failed: %v", err)
	}
	fileContentBlob, err := Enc_then_mac_hash(fileObj.Key, IV1, fileContentBlobBytes)
	if err != nil {
		return fmt.Errorf("encrypt file failed: %v", err)
	}
	fileContentBlobBytesEnc, err := json.Marshal(fileContentBlob)
	if err != nil {
		return fmt.Errorf("marshal encrypted file blob failed: %v", err)
	}
	userlib.DatastoreSet(fileContentUUID, fileContentBlobBytesEnc)

	// Load old tail node and link it to the new node
	oldTailUUID := fileObj.Tail
	oldTailData, ok := userlib.DatastoreGet(oldTailUUID)
	if !ok {
		return fmt.Errorf("AppendToFile: old tail node not found in datastore")
	}
	var encryptedTailBlob EncryptedBlob
	if err = json.Unmarshal(oldTailData, &encryptedTailBlob); err != nil {
		return errors.New("AppendToFile: failed to unmarshal file object blob")
	}
	oldTailPlain, err := Mac_hash_then_decrypt(fileObj.Key, encryptedTailBlob)
	if err != nil {
		return fmt.Errorf("AppendToFile: old tail node integrity check failed")
	}
	var oldTail FileContent
	if err = json.Unmarshal(oldTailPlain, &oldTail); err != nil {
		return fmt.Errorf("AppendToFile: failed to unmarshal old tail node")
	}
	oldTail.Next = fileContentUUID

	// Re-encrypt updated old tail and store
	oldTailBytes, err := json.Marshal(oldTail)
	if err != nil {
		return fmt.Errorf("AppendToFile: failed to marshal updated tail node: %v", err)
	}
	IV2 := userlib.RandomBytes(16)
	oldTailEnc, err := Enc_then_mac_hash(fileObj.Key, IV2, oldTailBytes)
	if err != nil {
		return fmt.Errorf("AppendToFile: failed to encrypt updated tail node: %v", err)
	}
	oldTailEncBytes, _ := json.Marshal(oldTailEnc)
	userlib.DatastoreSet(oldTailUUID, oldTailEncBytes)

	// Update file object’s tail and re-encrypt
	fileObj.Tail = fileContentUUID
	fileObjBytes, err = json.Marshal(fileObj)
	if err != nil {
		return fmt.Errorf("AppendToFile: failed to marshal updated file object: %v", err)
	}
	IV3 := userlib.RandomBytes(16)
	fileObjEnc, err := Enc_then_mac_hash(fileObj.Key, IV3, fileObjBytes)

	if err != nil {
		return fmt.Errorf("AppendToFile: failed to encrypt updated file object: %v", err)
	}
	fileObjEncBytes, err := json.Marshal(fileObjEnc)
	if err != nil {
		return fmt.Errorf("AppendToFile: failed to marshal encrypted file object: %v", err)
	}
	userlib.DatastoreSet(fileUUID, fileObjEncBytes)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Derive deterministic UUID for user’s encrypted file map
	mapUUIDBytes := userlib.Hash([]byte("filemap" + hex.EncodeToString(userdata.SK)))[:16]
	mapUUID, err := uuid.FromBytes(mapUUIDBytes)
	if err != nil {
		return nil, err
	}

	// Retrieve and decrypt user’s file map
	mapData, ok := userlib.DatastoreGet(mapUUID)
	if !ok {
		return nil, errors.New("LoadFile: file map not found")
	}

	var encMapBlob EncryptedBlob
	if err = json.Unmarshal(mapData, &encMapBlob); err != nil {
		return nil, errors.New("LoadFile: failed to unmarshal encrypted file map")
	}

	mapBytes, err := Mac_hash_then_decrypt(userdata.SK, encMapBlob)
	if err != nil {
		return nil, errors.New("LoadFile: file map integrity check failed")
	}

	var fileMap map[string]uuid.UUID
	if err = json.Unmarshal(mapBytes, &fileMap); err != nil {
		return nil, errors.New("LoadFile: failed to unmarshal file map")
	}

	// Locate file entry
	fileUUID, exists := fileMap[filename]
	if !exists {
		return nil, errors.New("LoadFile: file not found")
	}

	// Fetch and decrypt FileObject (metadata)
	encFileObj, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return nil, errors.New("LoadFile: file metadata not found")
	}

	// Step 4: Retrieve your copy of the FileKey (stored under something like "filekey_"+filename)
	keyUUIDBytes := userlib.Hash([]byte("filekey_" + filename + hex.EncodeToString(userdata.SK)))[:16]
	keyUUID, _ := uuid.FromBytes(keyUUIDBytes)
	encFileKeyBytes, ok := userlib.DatastoreGet(keyUUID)
	if !ok {
		return nil, errors.New("LoadFile: file key not found")
	}

	// Unmarshal into EncryptedBlob
	var encFileKey EncryptedBlob
	if err := json.Unmarshal(encFileKeyBytes, &encFileKey); err != nil {
		return nil, errors.New("LoadFile: failed to unmarshal file key blob")
	}

	// Decrypt using user's SK
	fileKey, err := Mac_hash_then_decrypt(userdata.SK, encFileKey)
	if err != nil {
		return nil, errors.New("LoadFile: file key integrity check failed")
	}

	// Use FileKey to decrypt the actual file metadata
	var encFileObjBlob EncryptedBlob
	if err = json.Unmarshal(encFileObj, &encFileObjBlob); err != nil {
		return nil, errors.New("LoadFile: failed to unmarshal file object blob")
	}
	fileObjPlain, err := Mac_hash_then_decrypt(fileKey, encFileObjBlob)

	if err != nil {
		return nil, errors.New("LoadFile: file metadata integrity check failed")
	}

	var fileObj FileObject
	if err = json.Unmarshal(fileObjPlain, &fileObj); err != nil {
		return nil, errors.New("LoadFile: failed to unmarshal FileObject")
	}

	// Traverse linked list from Head to Tail
	currentUUID := fileObj.Head
	for currentUUID != uuid.Nil {
		nodeBytes, ok := userlib.DatastoreGet(currentUUID)
		if !ok {
			return nil, fmt.Errorf("LoadFile: missing content node %v", currentUUID)
		}

		var encNode EncryptedBlob
		if err = json.Unmarshal(nodeBytes, &encNode); err != nil {
			return nil, fmt.Errorf("LoadFile: failed to unmarshal content node %v", currentUUID)
		}

		nodePlain, err := Mac_hash_then_decrypt(fileObj.Key, encNode)
		if err != nil {
			return nil, fmt.Errorf("LoadFile: integrity check failed for node %v", currentUUID)
		}

		var node FileContent
		if err = json.Unmarshal(nodePlain, &node); err != nil {
			return nil, fmt.Errorf("LoadFile: failed to decode node %v", currentUUID)
		}

		content = append(content, node.Content...)
		currentUUID = node.Next
	}

	return content, nil
}

func (userdata *User) CreateInvitation(filename, recipient string) (invitationPtr uuid.UUID, err error) {
	// Locate user’s file map
	// Hash(SK || "filemap") → deterministic UUID
	// Load file map and find fileUUID for filename.

	mapUUIDBytes := userlib.Hash([]byte("filemap" + hex.EncodeToString(userdata.SK)))[:16]
	mapUUID, err := uuid.FromBytes(mapUUIDBytes)
	if err != nil {
		return uuid.Nil, err
	}

	// Retrieve and decrypt user’s file map
	mapData, ok := userlib.DatastoreGet(mapUUID)
	if !ok {
		return uuid.Nil, errors.New("CreateInvitation: file map not found")
	}
	var encMapBlob EncryptedBlob
	if err = json.Unmarshal(mapData, &encMapBlob); err != nil {
		return uuid.Nil, errors.New("CreateInvitation: failed to unmarshal map")
	}
	mapBytes, err := Mac_hash_then_decrypt(userdata.SK, encMapBlob)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: map integrity check failed")
	}
	var fileMap map[string]uuid.UUID
	if err = json.Unmarshal(mapBytes, &fileMap); err != nil {
		return uuid.Nil, errors.New("CreateInvitation: failed to unmarshal map")
	}

	// Look up target file
	fileUUID, exists := fileMap[filename]
	if !exists {
		return uuid.Nil, errors.New("CreateInvitation: file not found")
	}

	// Get recipient’s public key from keystore
	pubKey, ok := userlib.KeystoreGet(recipient)
	if !ok {
		return uuid.Nil, fmt.Errorf("CreateInvitation: recipient not found")
	}

	// Decrypt your FileObject to get file key
	// Use userdata.SK → decrypt fileUUID’s object → get fileObj.Key
	fileObjBytes, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return uuid.Nil, errors.New("CreateInvitation: file metadata not found")
	}

	// Retrieve your encrypted fileKey
	keyUUIDBytes := userlib.Hash([]byte("filekey_" + filename + hex.EncodeToString(userdata.SK)))[:16]
	keyUUID, _ := uuid.FromBytes(keyUUIDBytes)
	encFileKeyBytes, ok := userlib.DatastoreGet(keyUUID)
	if !ok {
		return uuid.Nil, errors.New("CreateInvitation: file key not found")
	}

	var encFileKey EncryptedBlob
	if err = json.Unmarshal(encFileKeyBytes, &encFileKey); err != nil {
		return uuid.Nil, errors.New("CreateInvitation: failed to unmarshal file key blob")
	}

	fileKey, err := Mac_hash_then_decrypt(userdata.SK, encFileKey)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: file key integrity check failed")
	}

	// Decrypt FileObject with fileKey
	var encFileObjBlob EncryptedBlob
	if err = json.Unmarshal(fileObjBytes, &encFileObjBlob); err != nil {
		return uuid.Nil, errors.New("CreateInvitation: failed to unmarshal file object blob")
	}

	fileObjPlain, err := Mac_hash_then_decrypt(fileKey, encFileObjBlob)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: file metadata integrity check failed")
	}

	var fileObj FileObject
	if err = json.Unmarshal(fileObjPlain, &fileObj); err != nil {
		return uuid.Nil, errors.New("CreateInvitation: failed to unmarshal FileObject")
	}

	// Create invitation struct
	invite := Invitation{
		FileUUID: fileUUID,
		FileKey:  fileObj.Key,
		FromUser: userdata.Username,
	}

	// Marshal invitation
	inviteBytes, err := json.Marshal(invite)
	if err != nil {
		return uuid.Nil, fmt.Errorf("CreateInvitation: marshal failed: %v", err)
	}

	// Encrypt invitation using recipient’s public key
	encInvite, err := userlib.PKEEnc(pubKey, inviteBytes)
	if err != nil {
		return uuid.Nil, fmt.Errorf("CreateInvitation: PKEEnc failed: %v", err)
	}

	// Compute a MAC over the ciphertext for integrity
	macKey := userlib.Hash([]byte(userdata.Username + recipient))[:16]
	mac, err := userlib.HMACEval(macKey, encInvite)
	if err != nil {
		return uuid.Nil, fmt.Errorf("CreateInvitation: HMAC integrity failed: %v", err)
	}
	// Combine ciphertext + MAC
	inviteBlob := append(encInvite, mac...)

	// Store in datastore
	inviteUUID := uuid.New()
	userlib.DatastoreSet(inviteUUID, inviteBlob)
	return inviteUUID, nil

}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Fetch invitation from datastore
	inviteData, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("AcceptInvitation: invitation not found")
	}

	// Split ciphertext and MAC (verify integrity)
	hashSize := len(userlib.Hash([]byte("example")))
	if len(inviteData) < hashSize {
		return errors.New("AcceptInvitation: invalid invitation format")
	}

	ciphertext := inviteData[:len(inviteData)-hashSize]
	storedMAC := inviteData[len(inviteData)-hashSize:]

	// Recompute expected MAC using sender+recipient HMAC key
	macKey := userlib.Hash([]byte(senderUsername + userdata.Username))[:16]
	expectedMAC, err := userlib.HMACEval(macKey, ciphertext)
	if err != nil {
		return fmt.Errorf("AcceptInvitation: HMAC eval failed: %v", err)
	}
	if !userlib.HMACEqual(storedMAC, expectedMAC) {
		return errors.New("AcceptInvitation: integrity check failed (MAC mismatch)")
	}

	// Decrypt invitation ciphertext with your private key
	plaintext, err := userlib.PKEDec(userdata.PrivateKey, ciphertext)
	if err != nil {
		return fmt.Errorf("AcceptInvitation: decryption failed: %v", err)
	}

	// Unmarshal Invitation
	var invite Invitation
	if err = json.Unmarshal(plaintext, &invite); err != nil {
		return fmt.Errorf("AcceptInvitation: failed to unmarshal invite: %v", err)
	}

	if _, ok := userlib.DatastoreGet(invite.FileUUID); !ok {
		return errors.New("AcceptInvitation: file no longer valid (revoked or deleted)")
	}

	// Check if invitation's file key is still valid
	fileBytes, ok := userlib.DatastoreGet(invite.FileUUID)
	if ok {
		var encFileBlob EncryptedBlob
		if err := json.Unmarshal(fileBytes, &encFileBlob); err != nil {
			return errors.New("AcceptInvitation: invalid file object (tampered or revoked)")
		}
		if _, err := Mac_hash_then_decrypt(invite.FileKey, encFileBlob); err != nil {
			return errors.New("AcceptInvitation: file revoked or invalid key")
		}
	}

	// Load or initialize recipient’s file map
	mapUUIDBytes := userlib.Hash([]byte("filemap" + hex.EncodeToString(userdata.SK)))[:16]
	mapUUID, err := uuid.FromBytes(mapUUIDBytes)
	if err != nil {
		return err
	}

	var fileMap map[string]uuid.UUID
	mapData, exists := userlib.DatastoreGet(mapUUID)
	if exists {
		var encMapBlob EncryptedBlob
		if err = json.Unmarshal(mapData, &encMapBlob); err != nil {
			return errors.New("AcceptInvitation: failed to unmarshal map blob")
		}
		mapBytes, err := Mac_hash_then_decrypt(userdata.SK, encMapBlob)
		if err != nil {
			return errors.New("AcceptInvitation: map integrity check failed")
		}
		if err = json.Unmarshal(mapBytes, &fileMap); err != nil {
			return errors.New("AcceptInvitation: failed to unmarshal map")
		}
	} else {
		fileMap = make(map[string]uuid.UUID)
	}

	// Check if filename already exists
	if _, exists := fileMap[filename]; exists {
		return errors.New("AcceptInvitation: filename already exists")
	}

	// Add shared file reference
	fileMap[filename] = invite.FileUUID

	// Re-encrypt and store file map
	mapBytes, err := json.Marshal(fileMap)
	if err != nil {
		return fmt.Errorf("AcceptInvitation: marshal map failed: %v", err)
	}
	IV := userlib.RandomBytes(16)
	encMap, err := Enc_then_mac_hash(userdata.SK, IV, mapBytes)
	if err != nil {
		return fmt.Errorf("AcceptInvitation: encrypt map failed: %v", err)
	}
	encMapBytes, err := json.Marshal(encMap)
	if err != nil {
		return fmt.Errorf("AcceptInvitation: failed to marshal encrypted map: %v", err)
	}
	userlib.DatastoreSet(mapUUID, encMapBytes)

	// Store recipient’s encrypted copy of fileKey
	keyUUIDBytes := userlib.Hash([]byte("filekey_" + filename + hex.EncodeToString(userdata.SK)))[:16]
	keyUUID, _ := uuid.FromBytes(keyUUIDBytes)

	encFileKey, err := Enc_then_mac_hash(userdata.SK, userlib.RandomBytes(16), invite.FileKey)
	if err != nil {
		return fmt.Errorf("AcceptInvitation: failed to encrypt file key: %v", err)
	}
	encFileKeyBytes, _ := json.Marshal(encFileKey)
	userlib.DatastoreSet(keyUUID, encFileKeyBytes)

	// Delete invitation
	userlib.DatastoreDelete(invitationPtr)

	return nil
}

func (userdata *User) RevokeAccess(filename string, targetUsername string) error {
	if _, ok := userlib.KeystoreGet(targetUsername); !ok {
		return errors.New("RevokeAccess: target user does not exist")
	}
	// Load user’s file map
	mapUUIDBytes := userlib.Hash([]byte("filemap" + hex.EncodeToString(userdata.SK)))[:16]
	mapUUID, _ := uuid.FromBytes(mapUUIDBytes)
	mapData, ok := userlib.DatastoreGet(mapUUID)
	if !ok {
		return errors.New("RevokeAccess: file map not found")
	}

	var encMapBlob EncryptedBlob
	if err := json.Unmarshal(mapData, &encMapBlob); err != nil {
		return errors.New("RevokeAccess: failed to unmarshal map blob")
	}
	mapBytes, err := Mac_hash_then_decrypt(userdata.SK, encMapBlob)
	if err != nil {
		return errors.New("RevokeAccess: map integrity check failed")
	}

	var fileMap map[string]uuid.UUID
	if err = json.Unmarshal(mapBytes, &fileMap); err != nil {
		return errors.New("RevokeAccess: failed to unmarshal map")
	}

	fileUUID, exists := fileMap[filename]
	if !exists {
		return errors.New("RevokeAccess: file not found")
	}

	// Decrypt the file object
	fileBytes, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return errors.New("RevokeAccess: file metadata not found")
	}

	var encFileObj EncryptedBlob
	if err = json.Unmarshal(fileBytes, &encFileObj); err != nil {
		return errors.New("RevokeAccess: failed to unmarshal file blob")
	}

	// Decrypt current file key
	keyUUIDBytes := userlib.Hash([]byte("filekey_" + filename + hex.EncodeToString(userdata.SK)))[:16]
	keyUUID, _ := uuid.FromBytes(keyUUIDBytes)
	encFileKeyBytes, ok := userlib.DatastoreGet(keyUUID)
	if !ok {
		return errors.New("RevokeAccess: file key not found")
	}

	var encFileKey EncryptedBlob
	if err = json.Unmarshal(encFileKeyBytes, &encFileKey); err != nil {
		return errors.New("RevokeAccess: failed to unmarshal file key")
	}
	fileKey, err := Mac_hash_then_decrypt(userdata.SK, encFileKey)
	if err != nil {
		return errors.New("RevokeAccess: file key integrity check failed")
	}

	filePlain, err := Mac_hash_then_decrypt(fileKey, encFileObj)
	if err != nil {
		return errors.New("RevokeAccess: file metadata integrity check failed")
	}

	var fileObj FileObject
	if err = json.Unmarshal(filePlain, &fileObj); err != nil {
		return errors.New("RevokeAccess: failed to unmarshal FileObject")
	}

	// Ownership check
	if fileObj.Owner != userdata.Username {
		return errors.New("RevokeAccess: only owner can revoke")
	}

	// Generate new key for file (rotating key)
	newKey := userlib.RandomBytes(16)

	// Re-encrypt all content nodes
	current := fileObj.Head
	for current != uuid.Nil {
		nodeBytes, ok := userlib.DatastoreGet(current)
		if !ok {
			return fmt.Errorf("RevokeAccess: node tampered or corrupted: %v", err)
		}
		var encNode EncryptedBlob
		if err := json.Unmarshal(nodeBytes, &encNode); err != nil {
			return fmt.Errorf("RevokeAccess: node tampered or corrupted: %v", err)
		}
		nodePlain, err := Mac_hash_then_decrypt(fileObj.Key, encNode)
		if err != nil {
			return fmt.Errorf("RevokeAccess: node integrity check failed: %v", err)
		}

		var node FileContent
		err = json.Unmarshal(nodePlain, &node)
		if err != nil {
			return fmt.Errorf("integrity check failed: %v", err)
		}
		IV := userlib.RandomBytes(16)
		newEnc, _ := Enc_then_mac_hash(newKey, IV, nodePlain)
		newEncBytes, _ := json.Marshal(newEnc)
		userlib.DatastoreSet(current, newEncBytes)

		current = node.Next
	}

	// Re-encrypt file object with new key
	fileObj.Key = newKey
	objBytes, _ := json.Marshal(fileObj)
	IV := userlib.RandomBytes(16)
	newEncObj, _ := Enc_then_mac_hash(newKey, IV, objBytes)
	newEncObjBytes, _ := json.Marshal(newEncObj)
	userlib.DatastoreSet(fileUUID, newEncObjBytes)

	// Update owner’s key reference
	newEncFileKey, _ := Enc_then_mac_hash(userdata.SK, userlib.RandomBytes(16), newKey)
	newEncFileKeyBytes, _ := json.Marshal(newEncFileKey)
	userlib.DatastoreSet(keyUUID, newEncFileKeyBytes)

	// Remove target user’s access
	targetKeyUUIDBytes := userlib.Hash([]byte("filekey_" + filename + hex.EncodeToString(userlib.Hash([]byte(targetUsername)))))[:16]
	targetKeyUUID, _ := uuid.FromBytes(targetKeyUUIDBytes)
	userlib.DatastoreDelete(targetKeyUUID)

	return nil
}
