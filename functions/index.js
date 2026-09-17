const {
  onCall,
  HttpsError
} = require("firebase-functions/v2/https");

const {
  onUserDeleted
} = require("firebase-functions/v2/identity");

const {
  initializeApp
} = require("firebase-admin/app");

const {
  getAuth
} = require("firebase-admin/auth");

const {
  getFirestore
} = require("firebase-admin/firestore");


initializeApp();


const db = getFirestore();
const adminAuth = getAuth();


/* =====================================================
   CHECK ADMIN
===================================================== */

async function verifyAdmin(request) {

  if (!request.auth) {

    throw new HttpsError(
      "unauthenticated",
      "Login required."
    );

  }


  const uid =
    request.auth.uid;


  const userDoc =
    await db
      .collection("users")
      .doc(uid)
      .get();


  if (!userDoc.exists) {

    throw new HttpsError(
      "permission-denied",
      "Admin profile not found."
    );

  }


  const data =
    userDoc.data();


  if (data.role !== "admin") {

    throw new HttpsError(
      "permission-denied",
      "Admin access required."
    );

  }

}


/* =====================================================
   DELETE USER
===================================================== */

exports.deleteUser =
onCall(
  async (request) => {

    await verifyAdmin(request);


    const targetUid =
      request.data?.uid;


    if (!targetUid) {

      throw new HttpsError(
        "invalid-argument",
        "User UID required."
      );

    }


    /*
      Admin को खुद delete करने से रोकें
    */

    if (
      targetUid === request.auth.uid
    ) {

      throw new HttpsError(
        "failed-precondition",
        "You cannot delete your own admin account."
      );

    }


    try {

      /*
        पहले Authentication user delete
      */

      await adminAuth
        .deleteUser(targetUid);


      /*
        Firestore profile भी delete
      */

      await db
        .collection("users")
        .doc(targetUid)
        .delete();


      return {

        success: true,

        uid: targetUid,

        message:
          "Authentication and Firestore user deleted."

      };


    } catch (error) {

      console.error(
        "Delete user error:",
        error
      );


      /*
        अगर Auth user पहले से मौजूद नहीं है,
        तब भी Firestore profile cleanup करें
      */

      if (
        error.code ===
        "auth/user-not-found"
      ) {

        await db
          .collection("users")
          .doc(targetUid)
          .delete();


        return {

          success: true,

          uid: targetUid,

          message:
            "Auth user was missing. Firestore profile cleaned."

        };

      }


      throw new HttpsError(
        "internal",
        error.message
      );

    }

  }
);


/* =====================================================
   AUTH → FIRESTORE SYNC
===================================================== */

/*
   अगर Firebase Console से manually
   Authentication user delete किया गया,
   तो उसका Firestore profile भी delete होगा.
*/

exports.syncDeletedAuthUser =
onUserDeleted(
  async (event) => {

    const uid =
      event.data.uid;


    if (!uid) {
      return;
    }


    try {

      await db
        .collection("users")
        .doc(uid)
        .delete();


      console.log(
        "Deleted Firestore profile for:",
        uid
      );


    } catch (error) {

      console.error(
        "Firestore cleanup error:",
        error
      );

    }

  }
);
