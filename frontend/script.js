// 🔴 BACKEND API (Local)
const API_URL = "http://127.0.0.1:5000/check";

// 🔥 PRE-WARM BACKEND
window.addEventListener("load", () => {
    fetch("http://127.0.0.1:5000")
        .then(() => console.log("Server warmed"))
        .catch(() => console.log("Warm failed"));
});

// -------------------- PHISHING CHECK --------------------
async function checkPhishing(retry = 2) {
    const url = document.getElementById("urlInput").value;
    const resultDiv = document.getElementById("result");
    const progressBar = document.getElementById("progressBar");
    const sourceDiv = document.getElementById("source");

    if (!url || !url.includes(".")) {
        resultDiv.innerText = "⚠️ Enter a valid URL";
        resultDiv.className = "result phishing";
        return;
    }

    // ✅ Reset state (FIXED BUG)
    resultDiv.className = "result checking";
    progressBar.style.width = "5%";
    if (sourceDiv) sourceDiv.innerText = "";

    // 🧠 Smart loading animation
    let messages = [
        "🔍 Scanning URL...",
        "🧠 AI analyzing patterns...",
        "🔐 Checking security layers..."
    ];

    let i = 0;
    let interval = setInterval(() => {
        resultDiv.innerText = messages[i % messages.length];
        i++;
    }, 1200);

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 60000);

        const response = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url }),
            signal: controller.signal
        });

        clearTimeout(timeout);

        if (!response.ok) throw new Error("Server error");

        const data = await response.json();
        clearInterval(interval);

        // ✅ Show result
        resultDiv.innerText = data.result;
        resultDiv.className = "result " + data.label.toLowerCase();

        // ✅ Source
        if (sourceDiv) {
            sourceDiv.innerText = "Detected by: " + (data.source || "System");
        }

        // ✅ Progress
        progressBar.style.width = data.label === "Safe" ? "90%" : "25%";

    } catch (error) {
        clearInterval(interval);

        if (retry === 2) {
            resultDiv.innerText = "⏳ Connecting to AI engine...";
            resultDiv.className = "result checking";
            progressBar.style.width = "10%";
            setTimeout(() => checkPhishing(1), 3000);

        } else if (retry === 1) {
            resultDiv.innerText = "🔄 Retrying secure connection...";
            resultDiv.className = "result checking";
            progressBar.style.width = "15%";
            setTimeout(() => checkPhishing(0), 4000);

        } else {
            resultDiv.innerText = "❌ Server busy, try again";
            resultDiv.className = "result phishing";
            progressBar.style.width = "0%";
        }
    }
}

// -------------------- NETWORK ANIMATION --------------------
const canvas = document.getElementById("bgCanvas");
const ctx = canvas.getContext("2d");

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

let particles = [];

for (let i = 0; i < 100; i++) {
    particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        dx: (Math.random() - 0.5),
        dy: (Math.random() - 0.5)
    });
}

function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    for (let i = 0; i < particles.length; i++) {
        for (let j = i; j < particles.length; j++) {
            let dx = particles[i].x - particles[j].x;
            let dy = particles[i].y - particles[j].y;
            let dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < 120) {
                ctx.strokeStyle = "rgba(56,189,248,0.1)";
                ctx.beginPath();
                ctx.moveTo(particles[i].x, particles[i].y);
                ctx.lineTo(particles[j].x, particles[j].y);
                ctx.stroke();
            }
        }
    }

    particles.forEach(p => {
        ctx.beginPath();
        ctx.arc(p.x, p.y, 2, 0, Math.PI * 2);
        ctx.fillStyle = "#38bdf8";
        ctx.fill();

        p.x += p.dx;
        p.y += p.dy;

        if (p.x < 0 || p.x > canvas.width) p.dx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.dy *= -1;
    });

    requestAnimationFrame(animate);
}

animate();

// -------------------- RESPONSIVE --------------------
window.addEventListener("resize", () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});