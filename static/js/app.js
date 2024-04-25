//menu 
document.addEventListener('DOMContentLoaded', function () {
    var menubtn = document.querySelector(".menu-btn");
    var menu = document.querySelector(".menu");

    menubtn.addEventListener('click', function () {
        // Alternar a visibilidade do menu
        if (menu.style.display === 'none') {
            menu.style.display = 'block';
        } else {
            menu.style.display = 'none';
        }
    });
});
const cadastrarbtn = document.querySelector(".cadastrarbtn")
const visualizarbtn = document.querySelector(".visualizarbtn")

const containercadastro = document.querySelector(".solicitar-form")
const containervisualizar = document.querySelector(".visualizar-cadastros")

visualizarbtn.addEventListener("click", ()=>{
    containervisualizar.style.display = "block"
    containercadastro.style.display = "none"
})
cadastrarbtn.addEventListener("click", ()=>{
    containercadastro.style.display = "block"
    containervisualizar.style.display = "none"
})

//Solicitações aprovadas tabela 
$(document).ready(function () {
    // Inicialize DataTable para a tabela de aprovações
    $('#aprovadas-table').DataTable({
        language: {
            url: 'https://cdn.datatables.net/plug-ins/1.10.25/i18n/Portuguese-Brasil.json'
        },
        order: [[1, 'asc']] // 0 é o índice da coluna de data, 'desc' para ordenação descendente
        // Adicione outras opções de DataTables conforme necessário
    });
});

function alterarFuncao(usuarioId) {
    // Obter o valor selecionado do campo de seleção
    var novaFuncao = document.getElementById('nova_funcao_' + usuarioId).value;

    // Enviar os dados para o servidor (você precisa implementar a rota no Flask para processar essa requisição)
    fetch('/alterar_funcao/' + usuarioId, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ nova_funcao: novaFuncao }),
    })
    .then(response => response.json())
    .then(data => {
        // Tratar a resposta do servidor (pode exibir uma mensagem de sucesso, atualizar a página, etc.)
        console.log(data);
    })
    .catch((error) => {
        console.error('Erro:', error);
    });
}


