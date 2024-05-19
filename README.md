# ESTOU-TA-VER: um Monitor para Integridade para Diretorias

## Descrição

ESTOU-TA-VER é um programa que monitora a integridade dos ficheiros dentro de uma diretoria especificada. Utiliza funções de hash, assinaturas digitais, e cifragem para detetar alterações nos ficheiros. Este programa é útil para garantir que os ficheiros não foram modificados, garantindo a integridade e segurança dos dados.

## Funcionalidades

- **Execução isolada**: O programa funciona apenas quando executado pelo utilizador.
- **Cálculo de Hash SHA256**: Calcula valores de hash SHA256 para todos os ficheiros na diretoria monitorada.
- **Cifragem da Base de Dados**: Cifra a base de dados com AES-128-CBC usando uma chave derivada de uma palavra-passe.
- **Assinaturas Digitais RSA**: Utiliza assinaturas digitais RSA para garantir a integridade dos ficheiros.
- **Monitoramento em Tempo Real**: Pode ser executado como um serviço em segundo plano, detetando alterações em tempo real.
- **Help Detalhado**: Inclui uma ajuda detalhada com instruções de uso, instalação e detalhes de implementação.

## Requisitos

- Python 3.6 ou superior
- Bibliotecas: watchdog, cryptography, rich

## Instalação

1. Clone o repositório:
    ```bash
    git clone https://github.com/CostaPT07/TecnologySecurity.git
    cd estou-ta-ver
    ```

2. Crie e ative um ambiente virtual (opcional, mas recomendado):
    ```bash
    python -m venv venv
    source venv/bin/activate  # No Windows, use `venv\Scripts\activate`
    ```

3. Instale as dependências:
    ```bash
    pip install watchdog cryptography rich
    ```

## Uso

Execute o script principal:
```bash
python main.py