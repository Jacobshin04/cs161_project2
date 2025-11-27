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
	//"strings"

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

type DummyPointer struct {
	Address uuid.UUID
}

type FileContentNode struct {
	Content []byte
	Next    uuid.UUID
}

type UserFileObject struct {
	HeadDummy uuid.UUID
	TailDummy uuid.UUID
	TreeDummy uuid.UUID
	FileKey   []byte
	Owner     string
}

type OwnershipNode struct {
	Username           string
	UserFileObjectUUID uuid.UUID
	Children           []OwnershipNode
}

// =====================
// Helper Functions
// =====================

// Given Symmetric K, IV and Plaintext returns Encrypted Blob
func EncAndMac(K []byte, IV []byte, message []byte) (blob EncryptedBlob, err error) {
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

// Given Symmetric K and Encrypted Blob, verifies Mac and returns Plaintext
func MacAndDec(K []byte, blob EncryptedBlob) (plaintext []byte, err error) {
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

// Slow hashes with salt.
func slowHash(pw []byte, salt []byte) (encryptedMessage []byte, e error) {
	// Salt length check
	if len(salt) != 16 {
		return nil, errors.New("invalid Salt length")
	}
	return userlib.Argon2Key(pw, salt, 16), nil
}

// Given SK and Filename returns deterministic UUID
func fileAnchorUUID(SK []byte, filename string) (uuid.UUID, error) {
	out, err := userlib.HashKDF(SK, []byte("file-anchor|"+filename))
	if err != nil || len(out) < 16 {
		return uuid.Nil, errors.New("failed to derive file anchor")
	}
	return uuid.FromBytes(out[:16])
}

// Given UUID, Plaintext and K, stores encrypted blob at UUID
func storeEncryptedAt(uuidKey uuid.UUID, key []byte, plaintext []byte) error {
	iv := userlib.RandomBytes(16)
	blob, err := EncAndMac(key, iv, plaintext)
	if err != nil {
		return err
	}
	b, err := json.Marshal(blob)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(uuidKey, b)
	return nil
}
// Given UUID, Key and Pointer to obejct, MacAndDec EncryptedBlob and stores in pointer 
func loadDecryptedAt(uuidKey uuid.UUID, key []byte, out interface{}) error {
	b, ok := userlib.DatastoreGet(uuidKey)
	if !ok {
		return errors.New("datastore key missing")
	}
	var blob EncryptedBlob
	if err := json.Unmarshal(b, &blob); err != nil {
		return errors.New("malformed encrypted blob")
	}
	pt, err := MacAndDec(key, blob)
	if err != nil {
		return err
	}
	return json.Unmarshal(pt, out)
}

// Given Head location and Key, reads file and returns bytes.
func readFileFromHead(head uuid.UUID, K []byte) ([]byte, error) {
	var total []byte
	cur := head
	for cur != uuid.Nil {
		var node FileContentNode
		if err := loadDecryptedAt(cur, K, &node); err != nil {
			return nil, err
		}
		total = append(total, node.Content...)
		cur = node.Next
	}
	return total, nil
}

// =====================
// User Functions
// =====================

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
	encUserBlob, err := EncAndMac(K1, userObjectIV[:], userObjectBytes)
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

	encSaltBlob, err := EncAndMac(K2, saltIV[:], salt[:16])
	if err != nil {
		return nil, err
	}

	encSaltBytes, err := json.Marshal(encSaltBlob)
	if err != nil {
		return nil, errors.New("InitUser: error while marshaling encrypted salt")
	}

	userlib.DatastoreSet(saltUUID, encSaltBytes)

	// Slow hash SK from password and salt
	SK, err := slowHash([]byte(password), salt[:16])
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

	encPrivBlob, err := EncAndMac(SK, privateKeyIV[:], privBytes)
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

	decryptedUserStruct, err := MacAndDec(K1, userRecord)
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

	saltBytes, err := MacAndDec(K2, saltBlob)
	if err != nil {
		return nil, errors.New("GetUser: salt MAC check failed or password incorrect")
	}

	// Slow hash to derive SK
	SK, err := slowHash([]byte(password), saltBytes)
	if err != nil {
		return nil, errors.New("GetUser: slowHash failed")
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

	privateKeyBytes, err := MacAndDec(SK, privateKeyBlob)
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
	if len(filename) == 0 {
		return errors.New("StoreFile: empty filename")
	}

	anchorUUID, err := fileAnchorUUID(userdata.SK, filename)
	if err != nil {
		return err
	}

	// If anchor exists, overwrite Head and Dummy nodes to point to new FileContentNode
	if anchorBytes, ok := userlib.DatastoreGet(anchorUUID); ok {
		var anchorBlob EncryptedBlob
		if err := json.Unmarshal(anchorBytes, &anchorBlob); err != nil {
			return errors.New("StoreFile: malformed anchor")
		}
		anchorPT, err := MacAndDec(userdata.SK, anchorBlob)
		if err != nil {
			return errors.New("StoreFile: anchor integrity failed")
		}
		var anchor DummyPointer
		if err := json.Unmarshal(anchorPT, &anchor); err != nil {
			return errors.New("StoreFile: anchor decode failed")
		}

		var ufo UserFileObject
		if err := loadDecryptedAt(anchor.Address, userdata.SK, &ufo); err != nil {
			return errors.New("StoreFile: UFO load failed")
		}

		K := ufo.FileKey
		newNodeUUID := uuid.New()
		node := FileContentNode{Content: content, Next: uuid.Nil}
		nodeBytes, _ := json.Marshal(node)
		if err := storeEncryptedAt(newNodeUUID, K, nodeBytes); err != nil {
			return err
		}

		headDummy := DummyPointer{Address: newNodeUUID}
		tailDummy := DummyPointer{Address: newNodeUUID}
		hdBytes, _ := json.Marshal(headDummy)
		tdBytes, _ := json.Marshal(tailDummy)

		if err := storeEncryptedAt(ufo.HeadDummy, K, hdBytes); err != nil {
			return err
		}
		if err := storeEncryptedAt(ufo.TailDummy, K, tdBytes); err != nil {
			return err
		}
		return nil
	}

	// New Key K for file.
	K := userlib.RandomBytes(16)

	// Create new NodeUUID make it point to enc FileContentNode with K
	nodeUUID := uuid.New()
	node := FileContentNode{Content: content, Next: uuid.Nil}
	nodeBytes, _ := json.Marshal(node)
	if err := storeEncryptedAt(nodeUUID, K, nodeBytes); err != nil {
		return err
	}

	// Create Head and Tail dummmies to point to new NodeUUID and store them.
	headDummyUUID := uuid.New()
	tailDummyUUID := uuid.New()
	headDummy := DummyPointer{Address: nodeUUID}
	tailDummy := DummyPointer{Address: nodeUUID}
	hdBytes, _ := json.Marshal(headDummy)
	tdBytes, _ := json.Marshal(tailDummy)
	if err := storeEncryptedAt(headDummyUUID, K, hdBytes); err != nil {
		return err
	}
	if err := storeEncryptedAt(tailDummyUUID, K, tdBytes); err != nil {
		return err
	}

	// Init OwnershipTree root and TreeDummy
	treeUUID := uuid.New()
	treeDummyUUID := uuid.New()
	root := OwnershipNode{
		Username:           userdata.Username,
		UserFileObjectUUID: uuid.Nil,
		Children:           []OwnershipNode{},
	}
	rootBytes, _ := json.Marshal(root)
	if err := storeEncryptedAt(treeUUID, K, rootBytes); err != nil {
		return err
	}
	treeDummy := DummyPointer{Address: treeUUID}
	treeDummyBytes, _ := json.Marshal(treeDummy)
	if err := storeEncryptedAt(treeDummyUUID, K, treeDummyBytes); err != nil {
		return err
	}

	// UserFileObject.
	ufoUUID := uuid.New()
	ufo := UserFileObject{
		HeadDummy: headDummyUUID,
		TailDummy: tailDummyUUID,
		TreeDummy: treeDummyUUID,
		FileKey:   K,
		Owner:     userdata.Username,
	}
	ufoBytes, _ := json.Marshal(ufo)
	if err := storeEncryptedAt(ufoUUID, userdata.SK, ufoBytes); err != nil {
		return err
	}

	// Fix root to point to owner UFO.
	root.UserFileObjectUUID = ufoUUID
	rootBytes2, _ := json.Marshal(root)
	if err := storeEncryptedAt(treeUUID, K, rootBytes2); err != nil {
		return err
	}

	// Anchor dummy.
	anchor := DummyPointer{Address: ufoUUID}
	anchorBytes, _ := json.Marshal(anchor)
	if err := storeEncryptedAt(anchorUUID, userdata.SK, anchorBytes); err != nil {
		return err
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	if len(filename) == 0 {
		return errors.New("AppendToFile: empty filename")
	}

	// Get Anchor
	anchorUUID, err := fileAnchorUUID(userdata.SK, filename)
	if err != nil {
		return err
	}

	var anchor DummyPointer
	if err := loadDecryptedAt(anchorUUID, userdata.SK, &anchor); err != nil {
		return errors.New("AppendToFile: anchor missing or corrupted")
	}

	// Get UserFileObject from Anchor
	var ufo UserFileObject
	if err := loadDecryptedAt(anchor.Address, userdata.SK, &ufo); err != nil {
		return errors.New("AppendToFile: UFO load failed")
	}

	// Get Key, Go get Tail Object
	K := ufo.FileKey

	var tailDummy DummyPointer
	if err := loadDecryptedAt(ufo.TailDummy, K, &tailDummy); err != nil {
		return errors.New("AppendToFile: tail dummy corrupted")
	}
	oldTailUUID := tailDummy.Address

	// New node.
	newNodeUUID := uuid.New()
	newNode := FileContentNode{Content: content, Next: uuid.Nil}
	newNodeBytes, _ := json.Marshal(newNode)
	if err := storeEncryptedAt(newNodeUUID, K, newNodeBytes); err != nil {
		return err
	}

	// Update old tail.
	var oldTail FileContentNode
	if err := loadDecryptedAt(oldTailUUID, K, &oldTail); err != nil {
		return errors.New("AppendToFile: old tail corrupted")
	}
	oldTail.Next = newNodeUUID
	oldTailBytes, _ := json.Marshal(oldTail)
	if err := storeEncryptedAt(oldTailUUID, K, oldTailBytes); err != nil {
		return err
	}

	// Update tail dummy.
	tailDummy.Address = newNodeUUID
	tailDummyBytes, _ := json.Marshal(tailDummy)
	if err := storeEncryptedAt(ufo.TailDummy, K, tailDummyBytes); err != nil {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	if len(filename) == 0 {
		return nil, errors.New("LoadFile: empty filename")
	}

	anchorUUID, err := fileAnchorUUID(userdata.SK, filename)
	if err != nil {
		return nil, err
	}

	var anchor DummyPointer
	if err := loadDecryptedAt(anchorUUID, userdata.SK, &anchor); err != nil {
		return nil, errors.New("LoadFile: file not found")
	}

	var ufo UserFileObject
	if err := loadDecryptedAt(anchor.Address, userdata.SK, &ufo); err != nil {
		return nil, errors.New("LoadFile: UFO corrupted")
	}

	K := ufo.FileKey

	var headDummy DummyPointer
	if err := loadDecryptedAt(ufo.HeadDummy, K, &headDummy); err != nil {
		return nil, errors.New("LoadFile: head dummy corrupted")
	}

	return readFileFromHead(headDummy.Address, K)
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
