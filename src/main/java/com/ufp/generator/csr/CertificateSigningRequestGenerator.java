package com.ufp.generator.csr;

import java.util.HashMap;
import java.util.Map;
 
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.OutputStreamWriter;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import java.security.Security;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
 
import org.apache.log4j.Logger;

public class CertificateSigningRequestGenerator extends HttpServlet {
    private static String [] dnEntries = { "C", "L", "ST", "O", "OU" };
    private static Logger logger = Logger.getLogger(CertificateSigningRequestGenerator.class);
    private static SecureRandom secureRandom = new SecureRandom();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public PKCS10CertificationRequest generateRequest(KeyPair keyPair, String distinguishedName) throws Exception {
        return new PKCS10CertificationRequest("SHA256withRSA", new X500Principal(distinguishedName), keyPair.getPublic(), null, keyPair.getPrivate());
    }
        
    public KeyPair generateRSAKeyPair(int size) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(size, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
	}

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Map<String, String> workingMap = new HashMap<String, String>();
        Map<String, String[]> immutableMap = request.getParameterMap();
        
        for (String name : immutableMap.keySet()) {
            String value = immutableMap.get(name)[0];
            if ((value != null) && (value.length() > 0)) {
                workingMap.put(new String(name), new String(value));
            }
        }

        String commonName = "CN=" + workingMap.get("CN") + "/emailAddress=" + workingMap.get("emailAddress");
        workingMap.remove("CN");
        workingMap.remove("emailAddress");
        StringBuilder stringBuilder = new StringBuilder();
        for (String name : dnEntries) {
            logger.debug(name + "=" + workingMap.get(name));
            if (workingMap.containsKey(name)) {
                stringBuilder.append(name).append("=").append(workingMap.get(name)).append(", ");
            }
        }
        stringBuilder.append(commonName);
        String distinguishedName = stringBuilder.toString();
        logger.debug(distinguishedName);

        try {
            PEMWriter pemWriter = new PEMWriter(new FileWriter("identity.csr.pem"));
            KeyPair keyPair = generateRSAKeyPair(2048);
            PKCS10CertificationRequest pkcs10CertificationRequest = generateRequest(keyPair, distinguishedName);
            pemWriter.writeObject(pkcs10CertificationRequest);
            pemWriter.close();
            pemWriter = new PEMWriter(new FileWriter("identity.key.pem"));
            String password = generatePassword(16);
            pemWriter.writeObject(keyPair, "DESede", password.toCharArray(), secureRandom);
            pemWriter.close();
            FileWriter fileWriter = new FileWriter("secret.key");
            fileWriter.write(password);
            fileWriter.close();
        } catch (Exception e) {
            throw new ServletException(e);
        }
        
        response.sendRedirect("/success.html");
        //response.setStatus(HttpServletResponse.SC_OK);
        //response.getWriter().println("session=" + request.getSession(true).getId());
    }

   private String generatePassword(int size) {
        byte [] bytes = new byte[200];

        StringBuilder stringBuilder = new StringBuilder();
        while (stringBuilder.length() < size) {
            secureRandom.nextBytes(bytes);

            for (byte b : bytes) {
                if ((b > 0x20) && (b < 0x7E)) {
                    stringBuilder.append(Character.toString((char)b));
                }
            }
        }
        String generatedPassword = stringBuilder.toString().substring(0, size);
        logger.debug("generated password : " + generatedPassword);
        return generatedPassword;
    }
}