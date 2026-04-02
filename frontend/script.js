// -------------------- PHISHING CHECK --------------------
async function checkPhishing() {
    const url = document.getElementById("urlInput").value;
    const resultDiv = document.getElementById("result");
    const progressBar = document.getElementById("progressBar");
    const sourceDiv = document.getElementById("source");

    if (!url || !url.includes(".")) {
        resultDiv.innerText = "⚠️ Enter a valid URL";
        resultDiv.className = "result phishing";
        return;
    }

    resultDiv.innerText = "Scanning URL... ⚡";
    resultDiv.className = "result";
    progressBar.style.width = "20%";

    try {
        const response = await fetch("http://127.0.0.1:5000/check", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error("Server error");
        }

        const data = await response.json();

        // Show result
        resultDiv.innerText = data.result;
        resultDiv.className = "result " + data.label.toLowerCase();

        // Show source
        if (sourceDiv) {
            sourceDiv.innerText = "Detected by: " + (data.source || "System");
        }

        // Progress bar logic
        let percent = data.label === "Safe" ? 90 : 20;
        progressBar.style.width = percent + "%";

    } catch (error) {
        resultDiv.innerText = "❌ Server not running";
        resultDiv.className = "result danger";
        progressBar.style.width = "0%";
    }
}

// -------------------- PARTICLE BACKGROUND --------------------
const canvas = document.getElementById("bgCanvas");
const ctx = canvas.getContext("2d");

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

let particles = [];

for (let i = 0; i < 80; i++) {
    particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        radius: Math.random() * 2,
        dx: Math.random() - 0.5,
        dy: Math.random() - 0.5
    });
}

function animateParticles() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    particles.forEach(p => {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = "#38bdf8";
        ctx.fill();

        p.x += p.dx;
        p.y += p.dy;

        if (p.x < 0 || p.x > canvas.width) p.dx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.dy *= -1;
    });

    requestAnimationFrame(animateParticles);
}

animateParticles();

// Responsive canvas
window.addEventListener("resize", () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});