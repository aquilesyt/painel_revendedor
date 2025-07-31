
particlesJS("particles-js", {
  particles: {
    number: { value: 60 },
    color: { value: "#ff0000" },
    shape: { type: "circle" },
    opacity: { value: 0.6 },
    size: { value: 3 },
    move: { enable: true, speed: 1.5 }
  }
});

function toggleTabela() {
  const tabela = document.getElementById("tabelaIOS");
  tabela.style.display = tabela.style.display === "none" ? "block" : "none";
}

function salvarPix() {
  const chave = document.getElementById("chavePix").value;
  alert("Chave Pix salva: " + chave);
}

function solicitarSaque() {
  alert("Solicitação de saque enviada com sucesso!");
}
