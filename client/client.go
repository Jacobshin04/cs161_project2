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

// symmetric encryption and then MAC
func Enc_then_mac_hash(K []byte, IV []byte, message []byte) (blob EncryptedBlob, err error) {
	// IV length check
	if len(IV) != 16 {
		return EncryptedBlob{}, errors.New("invalid IV length")
	}

	KDF_output, err := userlib.HashKDF(K, []byte("key one"))
	if err != nil {
		return EncryptedBlob{}, err
	}
	K1 := KDF_output[:16]
	K2 := KDF_output[16:32]

	ciphertext := userlib.SymEnc(K1, IV, message)
	mac, err := userlib.HMACEval(K2, ciphertext)
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

func slow_hash(pw []byte, salt []byte) (encryptedMessage []byte, mac []byte, e error) {
	// Salt length check
	if len(salt) != 16 {
		return nil, nil, errors.New("invalid Salt length")
	}
	userlib.Argon2Key(pw, salt, 16)
}

func Mac_hash_then_decrypt(K []byte, blob EncryptedBlob) (plaintext []byte, err error) {
	// Check IV length
	if len(blob.IV) != 16 {
		return nil, errors.New("invalid IV length")
	}
	if len(blob.Ciphertext) == 0 {
		return nil, errors.New("empty ciphertext")
	}

	// Derive encryption and MAC keys from K
	KDF_output, err := userlib.HashKDF(K, []byte("key one"))
	if err != nil {
		return nil, err
	}
	K1 := KDF_output[:16]
	K2 := KDF_output[16:32]

	// Check MAC
	expectedMac, err := userlib.HMACEval(K2, blob.Ciphertext)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(expectedMac, blob.MAC) {
		return nil, errors.New("MAC mismatch")
	}

	plaintext = userlib.SymDec(K1, blob.Ciphertext)
	return plaintext, nil
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	// Check length of  username is non zero
	if len(username) == 0 {
		return nil, errors.New("Lenght of username cannot be 0")
	}
	// Username = uuid.FromBytes(hash(username)[0:16]) and Hash the PW = SK.
	var user, e = uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if e != nil {
		return nil, errors.New("username failed to create")
	}
	// TO DO: Remove. Just for testing purposes that user is length 16
	if len(user) != 16 {
		return nil, errors.New("Length of user is not 16")
	}
	// Check if the username exists in Datastore
	var value, ok = userlib.DatastoreGet(user)
	if ok {
		return nil, fmt.Errorf("username %q already exists", username)
	}

	// Generate SaltUUID, PrivateKeyUUID, and IV with UUID.new.
	var SaltUUID = uuid.New()
	var PrivateKeyUUID = uuid.New()
	var UserObjectIV = uuid.New()

	//In datastore Username maps to IV || Encrypt_then_mac_hash(SK1, IV, {SaltUUID, PrivateKeyUUID})

	userObject := UserObject{
		SaltUUID:       SaltUUID,
		PrivateKeyUUID: PrivateKeyUUID,
	}

	var userObjectBytes, err_userObjectBytes = json.Marshal(userObject)
	if err_userObjectBytes != nil {
		return nil, errors.New("Error while marshal user object")
	}

	// Generate keys from password
	var K = userlib.Hash([]byte(password))
	KDF_output, err := userlib.HashKDF(K, []byte("key one"))
	if err != nil {
		return nil, errors.New("Key generstion failed")
	}
	K1 := KDF_output[:16]
	K2 := KDF_output[16:32]

	// Encrypt user object (bytes)
	var enc_blob, err = Enc_then_mac_hash(K1, UserObjectIV[:], userObjectBytes)

}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// Step 0: Input validation
	if len(username) == 0 {
		return nil, errors.New("GetUser: username cannot be empty")
	}
	fmt.Println("GetUser: Starting for", username)

	// Step 1: Compute deterministic UUID for username
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, errors.New("GetUser: failed to compute UUID for username")
	}
	fmt.Println("GetUser: Computed UUID for username")

	data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("GetUser: user does not exist in datastore")
	}
	fmt.Println("GetUser: Found user struct in datastore")

	// Step 2: Derive fastSK, SK1, SK2
	fastSK := userlib.Hash([]byte(password))
	KDF_output, err := userlib.HashKDF(fastSK, []byte("key one"))
	if err != nil {
		return nil, errors.New("GetUser: HashKDF failed for password")
	}
	SK1 := KDF_output[:16]
	SK2 := KDF_output[16:32]
	fmt.Println("GetUser: Derived SK1 and SK2")

	// Step 3: Unmarshal and decrypt user metadata
	var userRecord EncryptedBlob
	err = json.Unmarshal(data, &userRecord)
	if err != nil {
		return nil, errors.New("GetUser: failed to unmarshal user record blob")
	}
	fmt.Println("GetUser: Unmarshaled user encrypted blob")

	decryptedUserStruct, err := Mac_hash_then_decrypt(SK1, userRecord)
	if err != nil {
		return nil, errors.New("GetUser: user struct MAC check failed or password incorrect")
	}
	fmt.Println("GetUser: Decrypted and validated user metadata")

	var userStruct UserObject
	err = json.Unmarshal(decryptedUserStruct, &userStruct)
	if err != nil {
		return nil, errors.New("GetUser: malformed user metadata after decryption")
	}
	fmt.Println("GetUser: Parsed SaltUUID and PrivateKeyUUID")

	// Step 4: Load and decrypt salt
	saltBlobBytes, ok := userlib.DatastoreGet(userStruct.SaltUUID)
	if !ok {
		return nil, errors.New("GetUser: salt not found in datastore")
	}
	fmt.Println("GetUser: Found salt blob")

	var saltBlob EncryptedBlob
	err = json.Unmarshal(saltBlobBytes, &saltBlob)
	if err != nil {
		return nil, errors.New("GetUser: malformed salt encrypted blob")
	}

	saltBytes, err := Mac_hash_then_decrypt(SK2, saltBlob)
	if err != nil {
		return nil, errors.New("GetUser: salt MAC check failed or password incorrect")
	}
	fmt.Println("GetUser: Decrypted and validated salt")

	// Step 5: Slow hash to derive SK
	SK := userlib.Argon2Key([]byte(password), saltBytes, 32)
	fmt.Println("GetUser: Derived SK with Argon2")

	// Step 6: Load and decrypt private key
	privateKeyBlobBytes, ok := userlib.DatastoreGet(userStruct.PrivateKeyUUID)
	if !ok {
		return nil, errors.New("GetUser: private key not found in datastore")
	}
	fmt.Println("GetUser: Found private key blob")

	var privateKeyBlob EncryptedBlob
	err = json.Unmarshal(privateKeyBlobBytes, &privateKeyBlob)
	if err != nil {
		return nil, errors.New("GetUser: malformed encrypted private key blob")
	}

	privateKeyBytes, err := Mac_hash_then_decrypt(SK, privateKeyBlob)
	if err != nil {
		return nil, errors.New("GetUser: private key MAC check failed or password incorrect")
	}
	fmt.Println("GetUser: Decrypted private key")

	var privateKey userlib.PKEDecKey
	err = json.Unmarshal(privateKeyBytes, &privateKey)
	if err != nil {
		return nil, errors.New("GetUser: private key could not be unmarshaled")
	}
	fmt.Println("GetUser: Parsed private key")

	// Step 7: Load public key from keystore
	publicKey, ok := userlib.KeystoreGet(username)
	if !ok {
		return nil, errors.New("GetUser: public key not found in keystore")
	}
	fmt.Println("GetUser: Retrieved public key from keystore")

	// Step 8: Construct and return user struct
	returnUser := &User{
		Username:   username,
		SK:         SK,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
	fmt.Println("GetUser: User struct constructed and returned")
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
