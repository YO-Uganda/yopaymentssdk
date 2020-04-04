/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package yo.co.ug.yopaymentssdk;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author josephtabajjwa
 */
public class YoPaymentsUtils {
    /*
    * @Param base64String: This is the base64 string you want to decode
    * 
    * return null | PublicKey resourse.
    */
    public static PublicKey getPublicKeyFromBase64String(String base64String) {
        try {
            
            Certificate cert=CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(base64String.getBytes("utf-8")));
            
            return cert.getPublicKey();
        } catch (CertificateException ex) {
            Logger.getLogger(YoPaymentsUtils.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            return null;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(YoPaymentsUtils.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }
    
    
    public static PublicKey getKey(String file) {
        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            FileInputStream is = new FileInputStream (file);
            X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
            PublicKey key = cer.getPublicKey();
            return key;
        } catch (CertificateException ex) {
            Logger.getLogger(YoPaymentsUtils.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(YoPaymentsUtils.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
        }
        return null;
    }
    
    public static String readAllBytesFromFile(String filePath) 
    {
        String content = "";
        try
        {
            content = new String ( Files.readAllBytes( Paths.get(filePath) ) );
        } 
        catch (IOException e) 
        {
            e.printStackTrace();
            return null;
        }
        return content;
    }
}
