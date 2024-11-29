import subprocess

class MultiTrustCore:
    def __init__(self, path_to_executable='./workspace/multosI2CInterface'):
        self.path_to_executable = path_to_executable

    def _run_command(self, *args):
        """
        Executa um comando do Multi-Trust Core utilizando subprocess.
        :param args: Argumentos do comando a ser executado.
        :return: Saída do comando como string.
        """
        try:
            process = subprocess.run(
                [self.path_to_executable] + list(args),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return process.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Erro ao executar o comando: {e.stderr.strip()}")

    def send_data(self, data):
        """
        Envia dados ao Multi-Trust Core.
        :param data: Dados a serem enviados.
        :return: Resposta do Multi-Trust Core.
        """
        return self._run_command('send', data)

    def receive_data(self):
        """
        Recebe dados do Multi-Trust Core.
        :return: Dados recebidos do Multi-Trust Core.
        """
        return self._run_command('receive')

    def test_connection(self):
        """
        Testa a conexão com o dispositivo Multi-Trust Core.
        :return: Status da conexão.
        """
        try:
            response = self._run_command('status')
            return {"status": "success", "message": response}
        except Exception as e:
            return {"status": "error", "message": str(e)}
