package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})
	Describe("Basic Custom Tests", func() {
		Specify("InitUser: Rejects duplicate usernames.", func() {
			userlib.DebugMsg("Creating first user Alice.")
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())

			_ = alice

			userlib.DebugMsg("Attempting to create a second user with the same username.")
			_, err = client.InitUser("alice", "newpassword")
			Expect(err).ToNot(BeNil()) // should error per spec
		})

		Specify("InitUser: Rejects empty usernames.", func() {
			userlib.DebugMsg("Attempting to create a user with an empty username.")
			_, err := client.InitUser("", "password123")
			Expect(err).ToNot(BeNil()) // per spec, must error
		})

		Specify("GetUser: Rejects login for a non-existing user.", func() {
			userlib.DebugMsg("Attempting to log in with a username that was never initialized.")
			_, err := client.GetUser("nonexistent_user", "password123")
			Expect(err).ToNot(BeNil()) // should error because user doesn’t exist
		})

		Specify("GetUser: Rejects login with incorrect password.", func() {
			userlib.DebugMsg("Creating a valid user 'bob'.")
			_, err := client.InitUser("bob", "correct_password")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to log in with the wrong password.")
			_, err = client.GetUser("bob", "wrong_password")
			Expect(err).ToNot(BeNil()) // must fail per spec
		})

		Specify("StoreFile: Overwrites existing file contents.", func() {
			userlib.DebugMsg("Initializing user Carol.")
			carol, err := client.InitUser("carol", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing initial file data: 'apple pie'")
			err = carol.StoreFile("dessert.txt", []byte("apple pie"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Overwriting file with new data: 'chocolate cake'")
			err = carol.StoreFile("dessert.txt", []byte("chocolate cake"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file to verify overwrite.")
			data, err := carol.LoadFile("dessert.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("chocolate cake"))) // confirm old data gone
		})

		Specify("LoadFile: Returns error for non-existent file.", func() {
			userlib.DebugMsg("Initializing user Dana.")
			dana, err := client.InitUser("dana", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to load a file that does not exist in Dana’s namespace.")
			_, err = dana.LoadFile("ghost_file.txt")
			Expect(err).ToNot(BeNil()) // should error per spec
		})

		Specify("AppendToFile: Returns error for non-existent file.", func() {
			userlib.DebugMsg("Initializing user Erin.")
			erin, err := client.InitUser("erin", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to append to a non-existent file.")
			err = erin.AppendToFile("missing_notes.txt", []byte("This should fail"))
			Expect(err).ToNot(BeNil()) // per spec, must error
		})

		Specify("CreateInvitation: Returns error when sharing a non-existent file.", func() {
			userlib.DebugMsg("Initializing user Frank.")
			frank, err := client.InitUser("frank", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to share a file that does not exist.")
			_, err = frank.CreateInvitation("imaginary.txt", "bob")
			Expect(err).ToNot(BeNil()) // must error per spec
		})

		Specify("CreateInvitation: Returns error when recipient user does not exist.", func() {
			userlib.DebugMsg("Initializing user Grace.")
			grace, err := client.InitUser("grace", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing a file to share.")
			err = grace.StoreFile("poem.txt", []byte("roses are red"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to share with a non-existent user.")
			_, err = grace.CreateInvitation("poem.txt", "nonexistent_user")
			Expect(err).ToNot(BeNil()) // must error per spec
		})

		Specify("AcceptInvitation: Returns error if recipient already has the given filename.", func() {
			userlib.DebugMsg("Initializing users Henry and Ivy.")
			henry, err := client.InitUser("henry", "password123")
			Expect(err).To(BeNil())

			ivy, err := client.InitUser("ivy", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Henry stores a file to share.")
			err = henry.StoreFile("shared.txt", []byte("secret data"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Henry creates an invitation for Ivy.")
			invitePtr, err := henry.CreateInvitation("shared.txt", "ivy")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Ivy creates a local file with the same name she’ll try to use.")
			err = ivy.StoreFile("shared.txt", []byte("my own file"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Ivy tries to accept the invitation using an existing filename.")
			err = ivy.AcceptInvitation("henry", invitePtr, "shared.txt")
			Expect(err).ToNot(BeNil()) // must error per spec
		})

		Specify("AcceptInvitation: Returns error for invalid (random) invitation UUID.", func() {
			userlib.DebugMsg("Initializing users Jack and Kelly.")
			jack, err := client.InitUser("jack", "password123")
			Expect(err).To(BeNil())

			kelly, err := client.InitUser("kelly", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Jack stores a file to share later.")
			err = jack.StoreFile("notes.txt", []byte("project details"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Kelly tries to accept using a random UUID that doesn't exist.")
			fakeUUID := uuid.New() // creates a random new UUID
			err = kelly.AcceptInvitation("jack", fakeUUID, "received.txt")
			Expect(err).ToNot(BeNil()) // must error per spec
		})

		Specify("AcceptInvitation: Fails if revoked before or after acceptance.", func() {
			userlib.DebugMsg("Initializing users Leo and Maya.")
			leo, err := client.InitUser("leo", "password123")
			Expect(err).To(BeNil())

			maya, err := client.InitUser("maya", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Leo stores a file to share.")
			err = leo.StoreFile("report.txt", []byte("classified content"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Leo creates an invitation for Maya.")
			invitePtr, err := leo.CreateInvitation("report.txt", "maya")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Leo immediately revokes access before Maya accepts.")
			err = leo.RevokeAccess("report.txt", "maya")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Maya tries to accept the revoked invitation (should fail).")
			err = maya.AcceptInvitation("leo", invitePtr, "shared_report.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Leo creates another invitation for Maya.")
			invitePtr2, err := leo.CreateInvitation("report.txt", "maya")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Maya accepts the new invitation successfully.")
			err = maya.AcceptInvitation("leo", invitePtr2, "shared_report2.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Leo revokes Maya's access after acceptance.")
			err = leo.RevokeAccess("report.txt", "maya")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Maya tries to load the file after being revoked (should fail).")
			_, err = maya.LoadFile("shared_report2.txt")
			Expect(err).ToNot(BeNil()) // should fail per spec
		})

		Specify("AcceptInvitation: Fails when the same invitation is accepted multiple times.", func() {
			userlib.DebugMsg("Initializing users Nick and Olivia.")
			nick, err := client.InitUser("nick", "password123")
			Expect(err).To(BeNil())

			olivia, err := client.InitUser("olivia", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Nick stores a file to share.")
			err = nick.StoreFile("draft.txt", []byte("initial document"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Nick creates an invitation for Olivia.")
			invitePtr, err := nick.CreateInvitation("draft.txt", "olivia")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Olivia accepts the invitation the first time (should succeed).")
			err = olivia.AcceptInvitation("nick", invitePtr, "shared_draft.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Olivia tries to accept the same invitation again (should fail).")
			err = olivia.AcceptInvitation("nick", invitePtr, "shared_draft_copy.txt")
			Expect(err).ToNot(BeNil()) // must error per spec
		})

		Specify("RevokeAccess: Revoking one invitation does not affect other users with separate invitations.", func() {
			userlib.DebugMsg("Initializing users Parker, Quinn, and Riley.")
			parker, err := client.InitUser("parker", "password123")
			Expect(err).To(BeNil())

			quinn, err := client.InitUser("quinn", "password123")
			Expect(err).To(BeNil())

			riley, err := client.InitUser("riley", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Parker stores a file to share.")
			err = parker.StoreFile("design.txt", []byte("top secret design"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Parker creates two invitations for Quinn and Riley.")
			inviteQ, err := parker.CreateInvitation("design.txt", "quinn")
			Expect(err).To(BeNil())
			inviteR, err := parker.CreateInvitation("design.txt", "riley")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Both recipients accept their invitations.")
			err = quinn.AcceptInvitation("parker", inviteQ, "shared_q.txt")
			Expect(err).To(BeNil())
			err = riley.AcceptInvitation("parker", inviteR, "shared_r.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Parker revokes Quinn’s access.")
			err = parker.RevokeAccess("design.txt", "quinn")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Quinn should now lose access.")
			_, err = quinn.LoadFile("shared_q.txt")
			Expect(err).ToNot(BeNil()) // must fail

			userlib.DebugMsg("Riley should still have access to the file.")
			data, err := riley.LoadFile("shared_r.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("top secret design"))) // Riley still can read
		})

		Specify("RevokeAccess: Non-owner cannot revoke access.", func() {
			userlib.DebugMsg("Initializing users Sam, Taylor, and Uma.")
			sam, err := client.InitUser("sam", "password123")
			Expect(err).To(BeNil())

			taylor, err := client.InitUser("taylor", "password123")
			Expect(err).To(BeNil())

			uma, err := client.InitUser("uma", "password123")
			Expect(err).To(BeNil())

			_ = uma

			userlib.DebugMsg("Sam stores a file and shares it with Taylor.")
			err = sam.StoreFile("project.txt", []byte("phase one complete"))
			Expect(err).To(BeNil())
			inviteT, err := sam.CreateInvitation("project.txt", "taylor")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Taylor accepts the invitation.")
			err = taylor.AcceptInvitation("sam", inviteT, "shared_project.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Taylor attempts to revoke Uma’s access (should fail).")
			err = taylor.RevokeAccess("shared_project.txt", "uma")
			Expect(err).ToNot(BeNil()) // must error per spec
		})

		Specify("RevokeAccess: Returns error when revoking a non-existent filename.", func() {
			userlib.DebugMsg("Initializing user Victor.")
			victor, err := client.InitUser("victor", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to revoke access to a non-existent file.")
			err = victor.RevokeAccess("missing.txt", "someuser")
			Expect(err).ToNot(BeNil()) // must error per spec
		})

		Specify("RevokeAccess: Returns error when target user does not exist.", func() {
			userlib.DebugMsg("Initializing user Wendy.")
			wendy, err := client.InitUser("wendy", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing a file that Wendy owns.")
			err = wendy.StoreFile("story.txt", []byte("once upon a time"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to revoke access from a user that does not exist.")
			err = wendy.RevokeAccess("story.txt", "ghost_user")
			Expect(err).ToNot(BeNil()) // must error per spec
		})

		Specify("RevokeAccess: Revoked user cannot StoreFile after revocation.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())

			bob, err := client.InitUser("bob", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice stores a file and shares it with Bob.")
			err = alice.StoreFile("project.txt", []byte("version 1"))
			Expect(err).To(BeNil())

			invitePtr, err := alice.CreateInvitation("project.txt", "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts the invitation.")
			err = bob.AcceptInvitation("alice", invitePtr, "shared_project.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes Bob’s access.")
			err = alice.RevokeAccess("project.txt", "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob tries to overwrite the revoked file (should fail).")
			err = bob.StoreFile("shared_project.txt", []byte("malicious update"))
			Expect(err).ToNot(BeNil()) // per spec, must fail after revocation
		})

		Specify("RevokeAccess: Revoked user and their descendants lose access, others retain access.", func() {
			userlib.DebugMsg("Initializing users: Owner Alice, Bob, Charlie, and Dave.")
			alice, err := client.InitUser("alice", "password123")
			Expect(err).To(BeNil())

			bob, err := client.InitUser("bob", "password123")
			Expect(err).To(BeNil())

			charlie, err := client.InitUser("charlie", "password123")
			Expect(err).To(BeNil())

			dave, err := client.InitUser("dave", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice stores a file and shares it with Bob and Charlie.")
			err = alice.StoreFile("plan.txt", []byte("initial plan"))
			Expect(err).To(BeNil())

			inviteBob, err := alice.CreateInvitation("plan.txt", "bob")
			Expect(err).To(BeNil())
			inviteCharlie, err := alice.CreateInvitation("plan.txt", "charlie")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob and Charlie accept their invitations.")
			err = bob.AcceptInvitation("alice", inviteBob, "shared_plan_bob.txt")
			Expect(err).To(BeNil())
			err = charlie.AcceptInvitation("alice", inviteCharlie, "shared_plan_charlie.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob shares the file with Dave.")
			inviteDave, err := bob.CreateInvitation("shared_plan_bob.txt", "dave")
			Expect(err).To(BeNil())
			err = dave.AcceptInvitation("bob", inviteDave, "shared_plan_dave.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes Bob’s access (should also revoke Dave’s).")
			err = alice.RevokeAccess("plan.txt", "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob and Dave should now lose access.")
			_, err = bob.LoadFile("shared_plan_bob.txt")
			Expect(err).ToNot(BeNil()) // Bob revoked
			_, err = dave.LoadFile("shared_plan_dave.txt")
			Expect(err).ToNot(BeNil()) // Dave is descendant of Bob

			userlib.DebugMsg("Charlie should still have access to the file.")
			data, err := charlie.LoadFile("shared_plan_charlie.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("initial plan"))) // Charlie unaffected
		})

	})
	Describe("Custom Security Tests", func() {
		Specify("GetUser: Detects tampering of stored user data.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err := client.InitUser("alice", "securepassword")
			Expect(err).To(BeNil())

			_ = alice

			userlib.DebugMsg("Simulating adversary tampering with Alice's stored data in Datastore.")
			for key := range userlib.DatastoreGetMap() {
				// Corrupt one of the stored values arbitrarily
				userlib.DatastoreSet(key, []byte("corrupted data"))
				break
			}

			userlib.DebugMsg("Attempting to log in as Alice on another device after tampering.")
			_, err = client.GetUser("alice", "securepassword")
			Expect(err).ToNot(BeNil()) // per spec, must detect tampering and return error
		})

		Specify("Tampering: Modifying datastore entries causes LoadFile/StoreFile to fail integrity check.", func() {
			userlib.DebugMsg("Initializing user Eve.")
			eve, err := client.InitUser("eve", "password123")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve stores a secure file.")
			err = eve.StoreFile("secret.txt", []byte("confidential data"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve loads the file normally to verify correct operation.")
			data, err := eve.LoadFile("secret.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("confidential data")))

			userlib.DebugMsg("Simulating datastore tampering by an adversary.")
			// Corrupt one stored entry (simulating malicious modification)
			for key := range userlib.DatastoreGetMap() {
				userlib.DatastoreSet(key, []byte("tampered content"))
				break
			}

			userlib.DebugMsg("Eve tries to load the file again — should detect tampering.")
			_, err = eve.LoadFile("secret.txt")
			Expect(err).ToNot(BeNil()) // must detect and reject modified data

			userlib.DebugMsg("Eve tries to store again — should also fail due to corrupted metadata.")
			err = eve.StoreFile("secret.txt", []byte("new data"))
			Expect(err).ToNot(BeNil()) // must fail integrity check
		})

		Specify("Tampering: Detects modified file contents in Datastore.", func() {
			userlib.DebugMsg("Initializing user Fred.")
			fred, err := client.InitUser("fred", "strongpassword")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Fred stores a secure file.")
			err = fred.StoreFile("diary.txt", []byte("Dear Diary, today was great!"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Fred loads the file normally.")
			data, err := fred.LoadFile("diary.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("Dear Diary, today was great!")))

			userlib.DebugMsg("Simulating attacker tampering with stored file contents.")
			// Corrupt one of Fred’s stored file chunks (random entry in Datastore)
			for key, value := range userlib.DatastoreGetMap() {
				if len(value) > 0 {
					// Flip a single byte to simulate bit tampering
					value[0] ^= 0xFF
					userlib.DatastoreSet(key, value)
					break
				}
			}

			userlib.DebugMsg("Fred tries to load the file after tampering — should fail integrity check.")
			_, err = fred.LoadFile("diary.txt")
			Expect(err).ToNot(BeNil()) // per spec, must detect and reject tampered file

			userlib.DebugMsg("Fred tries to overwrite the same file — should also fail since metadata is corrupted.")
			err = fred.StoreFile("diary.txt", []byte("new entry"))
			Expect(err).ToNot(BeNil()) // must fail integrity verification
		})

		Specify("GetUser: Detects tampering with stored password or user struct.", func() {
			userlib.DebugMsg("Initializing user Grace.")
			grace, err := client.InitUser("grace", "mypassword")
			Expect(err).To(BeNil())

			_ = grace

			userlib.DebugMsg("Simulating adversary tampering with Grace’s stored user data.")
			// Corrupt one entry in Datastore to simulate password or struct tampering
			for key, value := range userlib.DatastoreGetMap() {
				if len(value) > 0 {
					// Flip one byte to simulate data corruption
					value[0] ^= 0xAA
					userlib.DatastoreSet(key, value)
					break
				}
			}

			userlib.DebugMsg("Attempting to log in as Grace after tampering.")
			_, err = client.GetUser("grace", "mypassword")
			Expect(err).ToNot(BeNil()) // must detect tampering per spec
		})

		Specify("InitUser/GetUser: Detects tampering with username data in Datastore.", func() {
			userlib.DebugMsg("Initializing user Heidi.")
			heidi, err := client.InitUser("heidi", "strongpassword")
			Expect(err).To(BeNil())

			_ = heidi

			userlib.DebugMsg("Verifying Heidi can normally log in.")
			_, err = client.GetUser("heidi", "strongpassword")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Simulating attacker tampering with Heidi’s stored username entry.")
			// Corrupt one of Heidi’s datastore entries (which includes her username)
			for key, value := range userlib.DatastoreGetMap() {
				if len(value) > 0 {
					value[0] ^= 0xFF // flip a byte to simulate tampering
					userlib.DatastoreSet(key, value)
					break
				}
			}

			userlib.DebugMsg("Attempting to log in as Heidi after tampering.")
			_, err = client.GetUser("heidi", "strongpassword")
			Expect(err).ToNot(BeNil()) // must error per spec

			userlib.DebugMsg("Attempting to reinitialize Heidi with the same username should also fail.")
			_, err = client.InitUser("heidi", "newpassword")
			Expect(err).ToNot(BeNil()) // must fail because corrupted entry still exists
		})

	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})
})
