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

setTimeout("console.log('delayed')", 1000);

greet("Daniyal");
sendData();