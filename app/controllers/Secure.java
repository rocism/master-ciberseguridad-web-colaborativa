package controllers;


import models.User;
import play.i18n.Messages;
import play.mvc.Controller;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
public class Secure extends Controller {

    public static void login(){
        render();
    }

    public static void logout(){
        session.remove("password");
        login();
    }

    public static void authenticate(String username, String password){
        User u = User.loadUser(username);
        String newpass="";
        if (u != null){
            newpass= securizarPassword(password, u.getSalt());

            if (u.getPassword().equals(newpass)){
                session.put("username", username);
                session.put("password", password);
                Application.index();
            }else{
                flash.put("error", Messages.get("Public.login.error.credentials"));
                login();
            }
        }
        else {
            flash.put("error", Messages.get("Public.login.error.credentials"));
            login();
        }
		
	}
    public static String securizarPassword(String password, String salt) {
        byte [] saltbytes = Base64.getDecoder().decode(salt);

        String newPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(saltbytes);
            byte[] bytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            newPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return newPassword;
    }

    public static byte[] getSalt()  {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[32];
        random.nextBytes(salt);
        return salt;
    }

}
