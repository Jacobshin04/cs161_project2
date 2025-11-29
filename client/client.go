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
	Username     string
	SK           []byte
	PrivateKey   userlib.PKEDecKey
	PublicKey    userlib.PKEEncKey
	DSPublicKey  userlib.DSVerifyKey
	DSPrivateKey userlib.DSSignKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// { HELPER STRUCTS }
type EncryptedBlob struct {
	IV         []byte
	Ciphertext []byte
	MAC        []byte
}

type UserObject struct {
	SaltUUID         uuid.UUID
	PrivateKeyUUID   uuid.UUID
	DSPrivateKeyUUID uuid.UUID
}

type DummyPointer struct {
	Address uuid.UUID
}

type FileRoot struct {
	UFOUUID uuid.UUID
	FileKey []byte
}

type FileContentNode struct {
	Content []byte
	Next    uuid.UUID
}

type UserFileObject struct {
	HeadDummy uuid.UUID
	TailDummy uuid.UUID
	NodeDummy uuid.UUID
	Owner     string
	Signature []byte
}

type OwnershipNode struct {
	Username           string
	UserFileObjectUUID uuid.UUID
	Children           []OwnershipNode
}

// { HELPER FUNCTIONS }

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

// Given UUID, Key and Pointer to object, MacAndDec EncryptedBlob and stores in pointer
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

// Loads FileRoot given UUID and private key.
func loadFileRoot(priv userlib.PKEDecKey, rootUUID uuid.UUID, rootOut *FileRoot) error {
	ciphertext, ok := userlib.DatastoreGet(rootUUID)
	if !ok {
		return errors.New("loadFileRoot: FileRoot not found in datastore")
	}
	plaintext, err := userlib.PKEDec(priv, ciphertext)
	if err != nil {
		return errors.New("loadFileRoot: couldn't decrypt FileRoot with priv")
	}
	if err := json.Unmarshal(plaintext, rootOut); err != nil {
		return errors.New("loadFileRoot: not a valid FileRoot")
	}
	return nil
}

// Stores FileRoot using public-key encryption.
func storeFileRoot(pub userlib.PKEEncKey, rootUUID uuid.UUID, root *FileRoot) error {
	rootBytes, err := json.Marshal(root)
	if err != nil {
		return errors.New("storeFileRoot: failed to marshal FileRoot")
	}
	cipher, err := userlib.PKEEnc(pub, rootBytes)
	if err != nil {
		return errors.New("storeFileRoot: PKE encryption of FileRoot failed")
	}
	userlib.DatastoreSet(rootUUID, cipher)
	return nil
}

// canonicalizeUFO creates the canonical form by zeroing Signature+NodeDummy
func canonicalizeUFO(u UserFileObject) ([]byte, error) {
	tmp := u
	tmp.Signature = nil
	tmp.NodeDummy = uuid.Nil

	return json.Marshal(tmp)
}

// signUFO signs the canonical UFO using DS private key
func signUFO(u *UserFileObject, priv userlib.DSSignKey) error {
	canon, err := canonicalizeUFO(*u)
	if err != nil {
		return err
	}
	sig, err := userlib.DSSign(priv, canon)
	if err != nil {
		return err
	}
	u.Signature = sig
	return nil
}

// verifyUFO checks signature correctness
func verifyUFO(u *UserFileObject) error {
	if u.Owner == "" {
		return errors.New("verifyUFO: missing owner")
	}

	// Fetch owner's signature public key
	dsPub, ok := userlib.KeystoreGet(u.Owner + "|DS")
	if !ok {
		return errors.New("verifyUFO: owner's DS pubkey missing")
	}

	// Canonical form: signature removed, NodeDummy removed
	tmp := *u
	tmp.Signature = nil
	tmp.NodeDummy = uuid.Nil

	canon, err := json.Marshal(tmp)
	if err != nil {
		return errors.New("verifyUFO: canonical marshal failed")
	}

	if err := userlib.DSVerify(dsPub, canon, u.Signature); err != nil {
		return errors.New("verifyUFO: signature invalid")
	}

	return nil
}

func InitUser(username string, password string) (*User, error) {

	if len(username) == 0 {
		return nil, errors.New("InitUser: username cannot be empty")
	}

	// Deterministic user UUID from Hash(username[:16])
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, errors.New("InitUser: cannot derive UUID")
	}

	// Check for no duplicate username
	if _, exists := userlib.DatastoreGet(userUUID); exists {
		return nil, errors.New("InitUser: username already exists")
	}

	// Generate pointer UUIDs for user metadata.
	saltUUID := uuid.New()
	privateKeyUUID := uuid.New()
	dsPrivateKeyUUID := uuid.New()

	// Build user object. User Object to be encrypted and mac'd under deterministic password derived key.
	userMeta := UserObject{
		SaltUUID:         saltUUID,
		PrivateKeyUUID:   privateKeyUUID,
		DSPrivateKeyUUID: dsPrivateKeyUUID,
	}

	userMetaBytes, err := json.Marshal(userMeta)
	if err != nil {
		return nil, errors.New("InitUser: failed to marshal user metadata")
	}

	// Derive basic key from password. K1 for User Object and K2 for salt encryption.
	pwHash := userlib.Hash([]byte(password))
	KDFOut, err := userlib.HashKDF(pwHash[:16], []byte("user-meta"))
	if err != nil {
		return nil, errors.New("InitUser: HashKDF failed")
	}
	if len(KDFOut) < 32 {
		return nil, errors.New("InitUser: insufficient KDF output")
	}
	K1 := KDFOut[:16]   // key for userObject
	K2 := KDFOut[16:32] // will be used for salt encryption

	// Encrypt userMetaBytes under K1 and userUUID
	if err := storeEncryptedAt(userUUID, K1, userMetaBytes); err != nil {
		return nil, err
	}

	// Generate salt and encrypt under K2 and saltUUID.
	saltBytes := userlib.RandomBytes(16)
	saltJSON, err := json.Marshal(saltBytes)
	if err != nil {
		return nil, errors.New("InitUser: failed to marshal salt")
	}
	if err := storeEncryptedAt(saltUUID, K2, saltJSON); err != nil {
		return nil, err
	}

	// Generate SK with slow hash using password and salt
	SK, err := slowHash([]byte(password), saltBytes)
	if err != nil {
		return nil, err
	}

	// Generate RSA PKE Encryption Key Pair to Encrypt and Decrypt File Roots for sharing.
	pkePub, pkePriv, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("InitUser: PKEKeyGen failed")
	}
	userlib.KeystoreSet(username, pkePub)

	// Generate RSA DS Key Pair to have certified ownership of files.
	dsPriv, dsPub, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("InitUser: DSKeyGen failed")
	}
	userlib.KeystoreSet(username+"|DS", dsPub)

	// Encrypt PKE private key under SK
	privBytes, _ := json.Marshal(pkePriv)
	storeEncryptedAt(privateKeyUUID, SK, privBytes)

	// Encrypt DS private key under SK
	dsPrivBytes, _ := json.Marshal(dsPriv)
	storeEncryptedAt(dsPrivateKeyUUID, SK, dsPrivBytes)

	// Build local User struct
	u := &User{
		Username:     username,
		SK:           SK,
		PublicKey:    pkePub,
		PrivateKey:   pkePriv,
		DSPublicKey:  dsPub,
		DSPrivateKey: dsPriv,
	}

	return u, nil
}

func GetUser(username string, password string) (*User, error) {

	if len(username) == 0 {
		return nil, errors.New("GetUser: empty username")
	}

	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, errors.New("GetUser: hash UUID failed")
	}

	// Check if user exists before proceeding
	_, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("GetUser: user does not exist")
	}

	// Derive password based keys
	pwHash := userlib.Hash([]byte(password))
	KDFOut, err := userlib.HashKDF(pwHash[:16], []byte("user-meta"))
	if err != nil {
		return nil, errors.New("GetUser: HashKDF failed")
	}
	if len(KDFOut) < 32 {
		return nil, errors.New("GetUser: insufficient KDF out")
	}
	K1 := KDFOut[:16]
	K2 := KDFOut[16:32]

	// Load and decrypt user metadata

	var meta UserObject
	if err := loadDecryptedAt(userUUID, K1, &meta); err != nil {
		return nil, errors.New("GetUser: Incorrect password (Failed to decrypt metadata)")
	}

	// Load saltBytes
	var saltBytes []byte
	if err := loadDecryptedAt(meta.SaltUUID, K2, &saltBytes); err != nil {
		return nil, errors.New("GetUser: Incorrect password (Failed to decrypt Salt)")
	}

	// Recompute SK
	SK, err := slowHash([]byte(password), saltBytes)
	if err != nil {
		return nil, errors.New("GetUser: slowHash failed")
	}

	// Load PKE private key from Datastore, Load PKE public key from Keystore
	var pkePriv userlib.PKEDecKey
	if err := loadDecryptedAt(meta.PrivateKeyUUID, SK, &pkePriv); err != nil {
		return nil, errors.New("GetUser: Failed to derive SK")
	}

	pubKey, ok := userlib.KeystoreGet(username)
	if !ok {
		return nil, errors.New("GetUser: PKE public key missing")
	}

	// Load DS private key from datastore, Load DS public key from keystore
	var dsPriv userlib.DSSignKey
	if err := loadDecryptedAt(meta.DSPrivateKeyUUID, SK, &dsPriv); err != nil {
		return nil, errors.New("GetUser: Failed to derive SK (couldn't load dpriv)")
	}

	dsPub, ok := userlib.KeystoreGet(username + "|DS")
	if !ok {
		return nil, errors.New("GetUser: DS public key missing")
	}

	// Build User struct
	u := &User{
		Username:     username,
		SK:           SK,
		PublicKey:    pubKey,
		PrivateKey:   pkePriv,
		DSPublicKey:  dsPub,
		DSPrivateKey: dsPriv,
	}

	return u, nil
}

func (userdata *User) StoreFile(filename string, content []byte) error {
	if len(filename) == 0 {
		return errors.New("StoreFile: empty filename")
	}

	anchorUUID, err := fileAnchorUUID(userdata.SK, filename)
	if err != nil {
		return err
	}

	// If file exists overwrite
	if _, exists := userlib.DatastoreGet(anchorUUID); exists {

		// load anchor
		var anchor DummyPointer
		if err := loadDecryptedAt(anchorUUID, userdata.SK, &anchor); err != nil {
			return errors.New("StoreFile: corrupted anchor (overwrite)")
		}

		// load FileRoot
		var root FileRoot
		if err := loadFileRoot(userdata.PrivateKey, anchor.Address, &root); err != nil {
			return errors.New("StoreFile: FileRoot load fail (overwrite)")
		}

		K := root.FileKey
		ufoUUID := root.UFOUUID

		// load UFO
		var ufo UserFileObject
		if err := loadDecryptedAt(ufoUUID, K, &ufo); err != nil {
			return errors.New("StoreFile: UFO corrupted (overwrite)")
		}

		// verify signature
		if err := verifyUFO(&ufo); err != nil {
			return errors.New("StoreFile: signature invalid (overwrite)")
		}

		// overwrite content by creating new single node
		newNodeUUID := uuid.New()
		node := FileContentNode{Content: content, Next: uuid.Nil}
		nodeBytes, _ := json.Marshal(node)
		if err := storeEncryptedAt(newNodeUUID, K, nodeBytes); err != nil {
			return err
		}

		// update head/tail dummies
		headDummy := DummyPointer{Address: newNodeUUID}
		tailDummy := DummyPointer{Address: newNodeUUID}
		headDummyBytes, _ := json.Marshal(headDummy)
		tailDummyBytes, _ := json.Marshal(tailDummy)

		if err := storeEncryptedAt(ufo.HeadDummy, K, headDummyBytes); err != nil {
			return err
		}
		if err := storeEncryptedAt(ufo.TailDummy, K, tailDummyBytes); err != nil {
			return err
		}

		return nil
	}

	// File doesn't exist, Create new one.

	// New random file key
	K := userlib.RandomBytes(16)

	// Create content node
	nodeUUID := uuid.New()
	node := FileContentNode{Content: content, Next: uuid.Nil}

	nodeBytes, _ := json.Marshal(node)
	if err := storeEncryptedAt(nodeUUID, K, nodeBytes); err != nil {
		return errors.New("StoreFile: store node fail")
	}

	// Create Head/Tail dummies
	headDummyUUID := uuid.New()
	tailDummyUUID := uuid.New()
	headDummy := DummyPointer{Address: nodeUUID}
	tailDummy := DummyPointer{Address: nodeUUID}
	headDummyBytes, _ := json.Marshal(headDummy)
	tailDummyBytes, _ := json.Marshal(tailDummy)

	if err := storeEncryptedAt(headDummyUUID, K, headDummyBytes); err != nil {
		return err
	}
	if err := storeEncryptedAt(tailDummyUUID, K, tailDummyBytes); err != nil {
		return err
	}

	// Create OwnershipNode root
	rootNodeUUID := uuid.New()
	ownerRoot := OwnershipNode{
		Username:           userdata.Username,
		UserFileObjectUUID: uuid.Nil, // we fill after UFO is known
		Children:           []OwnershipNode{},
	}

	// Build UFO
	ufoUUID := uuid.New()
	ufo := UserFileObject{
		HeadDummy: headDummyUUID,
		TailDummy: tailDummyUUID,
		NodeDummy: rootNodeUUID,
		Owner:     userdata.Username,
		Signature: nil,
	}

	// Sign UFO
	if err := signUFO(&ufo, userdata.DSPrivateKey); err != nil {
		return errors.New("StoreFile: signing failed")
	}

	// store UFO
	ufoBytes, _ := json.Marshal(ufo)
	if err := storeEncryptedAt(ufoUUID, K, ufoBytes); err != nil {
		return errors.New("StoreFile: storing UFO failed")
	}

	// now store ownership node with correct UFO UUID
	ownerRoot.UserFileObjectUUID = ufoUUID
	ownBytes, _ := json.Marshal(ownerRoot)
	if err := storeEncryptedAt(rootNodeUUID, K, ownBytes); err != nil {
		return errors.New("StoreFile: store ownership node fail")
	}

	// Build FileRoot, Encrypt with Public key. Integrity protected by signature inside UFO
	fileRootUUID := uuid.New()
	fileRoot := FileRoot{
		UFOUUID: ufoUUID,
		FileKey: K,
	}

	if err := storeFileRoot(userdata.PublicKey, fileRootUUID, &fileRoot); err != nil {
		return errors.New("StoreFile: storing FileRoot failed")
	}

	// anchor with SK
	anchor := DummyPointer{Address: fileRootUUID}
	anchorBytes, _ := json.Marshal(anchor)
	if err := storeEncryptedAt(anchorUUID, userdata.SK, anchorBytes); err != nil {
		return errors.New("StoreFile: storing anchor failed")
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	if len(filename) == 0 {
		return errors.New("AppendToFile: empty filename")
	}

	anchorUUID, err := fileAnchorUUID(userdata.SK, filename)
	if err != nil {
		return err
	}

	// load anchor
	var anchor DummyPointer
	if err := loadDecryptedAt(anchorUUID, userdata.SK, &anchor); err != nil {
		return errors.New("AppendToFile: anchor corrupted")
	}

	// load FileRoot
	var root FileRoot
	if err := loadFileRoot(userdata.PrivateKey, anchor.Address, &root); err != nil {
		return errors.New("AppendToFile: FileRoot corrupted")
	}

	K := root.FileKey
	ufoUUID := root.UFOUUID

	// load UFO
	var ufo UserFileObject
	if err := loadDecryptedAt(ufoUUID, K, &ufo); err != nil {
		return errors.New("AppendToFile: UFO corrupted")
	}

	// verify signature
	if err := verifyUFO(&ufo); err != nil {
		return errors.New("AppendToFile: signature invalid")
	}

	// load tail dummy
	var tailDummy DummyPointer
	if err := loadDecryptedAt(ufo.TailDummy, K, &tailDummy); err != nil {
		return errors.New("AppendToFile: tail dummy corrupted")
	}

	oldTailUUID := tailDummy.Address

	// create new node
	newNodeUUID := uuid.New()
	newNode := FileContentNode{
		Content: content,
		Next:    uuid.Nil,
	}
	newNodeBytes, _ := json.Marshal(newNode)
	if err := storeEncryptedAt(newNodeUUID, K, newNodeBytes); err != nil {
		return errors.New("AppendToFile: storing new node failed")
	}

	// Patch old tail
	var oldTail FileContentNode
	if err := loadDecryptedAt(oldTailUUID, K, &oldTail); err != nil {
		return errors.New("AppendToFile: old tail corrupted")
	}
	oldTail.Next = newNodeUUID

	patched, _ := json.Marshal(oldTail)
	if err := storeEncryptedAt(oldTailUUID, K, patched); err != nil {
		return errors.New("AppendToFile: updating old tail failed")
	}

	// Update tail dummy
	tailDummy.Address = newNodeUUID
	tailDummyBytes, _ := json.Marshal(tailDummy)
	if err := storeEncryptedAt(ufo.TailDummy, K, tailDummyBytes); err != nil {
		return errors.New("AppendToFile: updating tail dummy failed")
	}

	return nil
}

func (userdata *User) LoadFile(filename string) ([]byte, error) {
	if len(filename) == 0 {
		return nil, errors.New("LoadFile: empty filename")
	}

	anchorUUID, err := fileAnchorUUID(userdata.SK, filename)
	if err != nil {
		return nil, err
	}

	// load anchor
	var anchor DummyPointer
	if err := loadDecryptedAt(anchorUUID, userdata.SK, &anchor); err != nil {
		return nil, errors.New("LoadFile: file not found")
	}

	// load FileRoot
	var root FileRoot
	if err := loadFileRoot(userdata.PrivateKey, anchor.Address, &root); err != nil {
		return nil, errors.New("LoadFile: FileRoot corrupted")
	}

	K := root.FileKey
	ufoUUID := root.UFOUUID

	// load UFO
	var ufo UserFileObject
	if err := loadDecryptedAt(ufoUUID, K, &ufo); err != nil {
		return nil, errors.New("LoadFile: UFO corrupted")
	}

	// verify signature
	if err := verifyUFO(&ufo); err != nil {
		return nil, errors.New("LoadFile: signature invalid")
	}

	// load head dummy
	var headDummy DummyPointer
	if err := loadDecryptedAt(ufo.HeadDummy, K, &headDummy); err != nil {
		return nil, errors.New("LoadFile: head dummy corrupted")
	}

	// read linked list
	data, err := readFileFromHead(headDummy.Address, K)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// Check non empty filename and recipient username.

	// Load and decrypt anchor of file to share

	// Load and decrypt FileRoot

	// Load UFO and verify integrity (owner's DS signature).

	// Load ownership tree from ufo.NodeDummy.

	// Append child node for the recipient under the sharer's node.

	// Store updated ownership tree.

	// Look up recipient's public key to encrypt their fileRoot and make sure recpient exists.

	// Create FileRoot for the recipient and store it under a fresh UUID.

	// Store in random UUID fileRoot

	return uuid.UUID{} , nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Ensure filename length is nonzero

	// Ensure recipient does not already have this filename.

	// Decrypt FileRoot from the invitation pointer using recipient's private key.

	// Load UFO and verify integrity.

	// Check Insert your own node in ownershipTree (Your own subtree)

	// Create anchor from name to fileRoot

	
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	return nil
}
