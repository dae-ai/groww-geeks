
  import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.1/firebase-app.js";
  import { getAuth, createUserWithEmailAndPassword } from  "https://www.gstatic.com/firebasejs/10.8.1/firebase-auth.js";
  import { getDatabase } from "https://www.gstatic.com/firebasejs/10.8.1/firebase-database.js";

  const firebaseConfig = {
    apiKey:"AIzaSyA4ru1hLqozyWWQSYTmQbLr5JNH6-ATf28",
    authDomain: "login-dd3b4.firebaseapp.com",
    projectId: "login-dd3b4",
    storageBucket: "login-dd3b4.appspot.com",
    messagingSenderId: "328496198056",
    appId: "1:328496198056:web:0445c1848b488eb42f2d9d"
  };

  // Initialize Firebase
  const app = initializeApp(firebaseConfig);
  const auth = getAuth();
  const database = getDatabase(app);


  submitData.addEventListener('click ', (e) => {
    var email = document.getElementById('email').value;
    var password = document.getElementById(' paw').value;

    createUserWithEmailAndPassword(auth,email,password)
    .then ((userCredential) => {
        const user = userCredential.user;
        alert('user created successfully');
    })
    .catch ((error) => {
        const errorCode = error.code;
        const errorMessage = error.message;
        alert(errorMessage);
    });

  });

 
