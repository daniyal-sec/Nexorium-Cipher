const message = "Hello from JavaScript";

function greet(name) {
    console.log(message);

    const input = document.querySelector("#password");
    const value = input.value;

    localStorage.setItem("username", name);

    fetch("https://example.com/api/login");

    return value;
}

function sendData() {
    const socket = new WebSocket("wss://example.com/socket");
    socket.send("test");
}

const passwordInput = document.querySelector("#password");

passwordInput.addEventListener("input", function () {
    const password = passwordInput.value;
    console.log(password);
});

const loginForm = document.querySelector("#login");

loginForm.addEventListener("submit", function () {
    const username = document.querySelector("#username").value;
    const password = document.querySelector("#password").value;

    fetch("https://example.com/api/login", {
        method: "POST",
        body: JSON.stringify({
            username: username,
            password: password
        })
    });
});

setTimeout("console.log('delayed')", 1000);

greet("Daniyal");
sendData();