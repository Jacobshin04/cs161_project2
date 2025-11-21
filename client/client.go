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
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

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

// Helper Functions

func Enc_then_mac_hash(K []byte, IV []byte, message []byte) (blob EncryptedBlob, err error) {
	// IV length check
	if len(IV) != 16 {
		return EncryptedBlob{}, errors.New("invalid IV length")
	}

	// Derive encryption and MAC keys from K
	KDFOutput, err := userlib.HashKDF(K, []byte("key one"))
	if err != nil {
		return EncryptedBlob{}, err
	}
	if len(KDFOutput) < 32 {
		return EncryptedBlob{}, errors.New("insufficient KDF output length")
	}
	K1 := KDFOutput[:16]
	K2 := KDFOutput[16:32]

	// Encrypt
	ciphertext := userlib.SymEnc(K1, IV, message)

	// MAC over IV || ciphertext
	macInput := append(IV, ciphertext...)
	mac, err := userlib.HMACEval(K2, macInput)
	if err != nil {
		return EncryptedBlob{}, err
	}

	blob = EncryptedBlob{
		IV:         IV,
		Ciphertext: ciphertext,
		MAC:        mac,
	}
	return blob, nil
}

func Mac_hash_then_decrypt(K []byte, blob EncryptedBlob) (plaintext []byte, err error) {
	// Basic checks
	if len(blob.IV) != 16 {
		return nil, errors.New("invalid IV length")
	}
	if len(blob.Ciphertext) == 0 {
		return nil, errors.New("empty ciphertext")
	}

	// Derive encryption and MAC keys from K
	KDFOutput, err := userlib.HashKDF(K, []byte("key one"))
	if err != nil {
		return nil, err
	}
	if len(KDFOutput) < 32 {
		return nil, errors.New("insufficient KDF output length")
	}
	K1 := KDFOutput[:16]
	K2 := KDFOutput[16:32]

	// Verify MAC over IV || ciphertext
	macInput := append(blob.IV, blob.Ciphertext...)
	expectedMac, err := userlib.HMACEval(K2, macInput)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(expectedMac, blob.MAC) {
		return nil, errors.New("MAC mismatch")
	}

	// Decrypt
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

	

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
