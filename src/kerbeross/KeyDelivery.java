package kerbeross;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import javax.crypto.SecretKey;

public class KeyDelivery {

    public KeyDelivery() {
    }

    //  Envio con sockets de las claves
    public void sendSecretKey(SecretKey secretKey, ServerSocket servSock) {
        try {
            Socket sock = servSock.accept();
            System.out.println("Conection Accepted mf");
            sock.getOutputStream().write(secretKey.getEncoded());
            sock.getOutputStream().flush();
            sock.close();
            servSock.close();
        } catch (IOException ex) {
            System.out.println(ex);
        }
    }
}
