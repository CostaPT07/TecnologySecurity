# Projeto SI (Segurança Informática)

## Descrição
Este projeto consiste na implementação de um programa de monitoramento de integridade para diretórios em Python. O programa utiliza funções de hash, cifras e HMAC para detectar alterações nos ficheiros dentro de um diretório selecionado pelo utilizador.

## Funcionalidades
- Calcula valores de hash SHA256 para todos os ficheiros num diretório.
- Cifra o ficheiro da base de dados com AES-128-CBC usando uma chave derivada de uma senha do utilizador.
- Armazena HMAC-SHA512 juntamente com os valores de hash e nomes de ficheiros na base de dados.
- Verifica a integridade dos ficheiros e notifica o utilizador sobre alterações detetadas.
- Gera e armazena uma nova base de dados atualizada em caso de alterações nos ficheiros.

## Requisitos de Instalação
- Python 3.x
- Bibliotecas Python: hashlib, cryptography

## Instruções de Uso
1. Clone este repositório no seu computador.
2. Ative o ambiente virtual (se estiver a usar um).
3. Instale as dependências do projeto:

"pip install -r requirements.txt"

4. Execute o programa principal:

python main.py

## Exemplo de Uso
- Após executar o programa, será solicitado a selecionar um diretório para monitorar.
- O programa calculará os valores de hash dos ficheiros no diretório e os armazenará numa base de dados cifrada.
- Nas execuções subsequentes, o programa verificará a integridade dos ficheiros e notificará sobre quaisquers alterações detetadas.

## Contribuições
Contribuições são bem-vindas! Sinta-se à vontade para enviar pull requests com melhorias, correções de bugs, etc.

## Licença
Este projeto é licenciado sob a [MIT License](LICENSE).
