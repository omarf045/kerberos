package kerbeross;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;

public class AuthCert {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        int AUTH_PORT = 5000;

        SecretKey secretTGS = new KeyManager().generateSecretKey();
        SecretKey secretCTGS = new KeyManager().generateSecretKey();
        SecretKey secretCV = new KeyManager().generateSecretKey();
        SecretKey secretV = new KeyManager().generateSecretKey();
        SecretKey secretC = new KeyManager().generateSecretKey();
        try {

            KeyDelivery kd = new KeyDelivery();

            //Clave del Client al Client
            ServerSocket ssC_C = new ServerSocket(AUTH_PORT);
            System.out.println("Esperando al Cliente...");
            kd.sendSecretKey(secretC, ssC_C);
            ServerSocket ssCTGS_C = new ServerSocket(AUTH_PORT);
            kd.sendSecretKey(secretCTGS, ssCTGS_C);
            System.out.println("Clave enviada al Cliente");
            
            //Clave del Client al AS
            ServerSocket ssC_AS = new ServerSocket(AUTH_PORT);
            System.out.println("Esperando al AS...");
            kd.sendSecretKey(secretC, ssC_AS);
            
            //Clave del Client/TGS al AS
            ServerSocket ssCTGS_AS = new ServerSocket(AUTH_PORT);
            kd.sendSecretKey(secretCTGS, ssCTGS_AS); 
            System.out.println("Llave Secreta Client/TGS: "+secretCTGS);
            
            //Clave del TGS al AS
            ServerSocket ssTGS_AS = new ServerSocket(AUTH_PORT);
            kd.sendSecretKey(secretTGS, ssTGS_AS);
            System.out.println("Clave enviada al AS");                      

            //Clave del TGS al TGS
            ServerSocket ssTGS_TGS = new ServerSocket(AUTH_PORT);
            System.out.println("Esperando al TGS...");
            kd.sendSecretKey(secretTGS, ssTGS_TGS);
            
            //Clave del Client/TGS al TGS
            ServerSocket ssCTGS_TGS = new ServerSocket(AUTH_PORT);
            kd.sendSecretKey(secretCTGS, ssCTGS_TGS);   
            
            //Clave del Servidor al TGS
            ServerSocket ssV_TGS = new ServerSocket(AUTH_PORT);
            kd.sendSecretKey(secretV, ssV_TGS);     
            
            //Clave del Client/Servidor al TGS
            ServerSocket ssCV_TGS = new ServerSocket(AUTH_PORT);
            kd.sendSecretKey(secretCV, ssCV_TGS);
            System.out.println("Clave enviada al TGS");  
            
            //Clave del Client/Servidor al V
            ServerSocket ssCV_V = new ServerSocket(AUTH_PORT);
            System.out.println("Esperando a V...");
            kd.sendSecretKey(secretCV, ssCV_V);

            //Clave del Servidor al V
            ServerSocket ssV_V = new ServerSocket(AUTH_PORT);
            kd.sendSecretKey(secretCV, ssV_V);
            System.out.println("Clave enviada al Servidor");       
            

        } 
        catch (IOException ex) {
            System.out.println("IOException: "+ex);
        }

    }

}
