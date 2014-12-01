package Shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.Ini;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author hyuchiha
 */
public class ShiroApi {

    private static final transient Logger log = LoggerFactory.getLogger(ShiroApi.class);

    private final DefaultSecurityManager defaultSecurityManager;
    private final Ini ini;
    private final Ini.Section usuarios;
    private final Ini.Section roles;
    Subject currentUser;

    /**
     * Método que crea el archivo .ini del shiro
     */
    public ShiroApi() {

        defaultSecurityManager = new DefaultSecurityManager();
        ini = new Ini();
        usuarios = ini.addSection(IniRealm.USERS_SECTION_NAME);
        roles = ini.addSection(IniRealm.ROLES_SECTION_NAME);

//        inicializarIni();
    }

    /**
     * Métodoque inicializa el .ini
     */
    public final void inicializarIni() {
        defaultSecurityManager.setRealm(new IniRealm(ini));
        SecurityUtils.setSecurityManager(defaultSecurityManager);
    }

    /**
     * Método que actualiza el archivo .ini
     */
    private void actualizar() {
        defaultSecurityManager.setRealm(new IniRealm(ini));
        SecurityUtils.setSecurityManager(defaultSecurityManager);
    }

    /**
     * Método que encripta la contraseña.
     *
     * @param encriptar
     * @return contraseña encriptada
     */
    public String encriptar(String encriptar) {
        Hash hash = new Md5Hash(encriptar);
        return hash.toBase64();
    }

    /**
     * Agrega un usuario al shiro.
     *
     * @param nombre
     * @param clave
     * @param rol
     */
    public void agregarCuenta(String nombre, String clave, String rol) {
//        String claveEncriptada = encriptar(clave);
        usuarios.put(nombre, clave + ", " + rol);
        log.info("Usuario agregado exitosamente");
        actualizar();
    }

    /**
     * Se agregan roles que se vayan a utilizar
     *
     * @param rol
     * @param Permisos
     */
    public void agregarRol(String rol, String Permisos) {
        roles.put(rol, Permisos);
        actualizar();
    }

    /**
     * Inicia sesión con nombre de usuario y clave
     *
     * @param nombre
     * @param clave
     * @return true si se inició sesión correctamente, false si no se pudo
     * inciar sesión
     */
    public boolean logIn(String nombre, String clave) {
        currentUser = SecurityUtils.getSubject();

        String password = encriptar(clave);

        UsernamePasswordToken token = new UsernamePasswordToken(nombre, password);
        token.setRememberMe(true);
        try {
            currentUser.login(token);
        } catch (UnknownAccountException uae) {
            log.info("No hay usuario con el nombre [" + token.getPrincipal() + "]");
        } catch (IncorrectCredentialsException ice) {
            log.info("Password para la cuenta [" + token.getPrincipal() + "] es incorrecto");
        } catch (LockedAccountException lae) {
            log.info("La cuenta del usuario [" + token.getPrincipal() + "] se encuentra bloqueada");
        }

        if (!currentUser.isAuthenticated()) {
            log.info("Error al iniciar sesión.");
        } else {
            log.info("Usuario [" + currentUser.getPrincipal() + "] inició sesión correctamente.");
        }
        return currentUser.isAuthenticated();
    }

    /**
     * Por si se requiere obtener el usuario que está logueado
     *
     * @return String
     *
     */
    public String getUsuario() {
        currentUser = SecurityUtils.getSubject();
        return currentUser.getPrincipal().toString();
    }

    /**
     * Método para cerrar la sesión del usuario
     */
    public void logOut() {
        currentUser = SecurityUtils.getSubject();
        currentUser.logout();
        log.info("Se ha cerrado sesión correctamente.");
    }

    /**
     * Método que verifica si un usuario tiene cierto rol
     *
     * @param rol
     * @return
     */
    public boolean hasRol(String rol) {
        boolean autentificarRol;
        if (currentUser.hasRole(rol)) {
            log.info("Usuario con rol: " + rol);
            autentificarRol = true;
        } else {
            log.info("Usuario sin rol: " + rol);
            autentificarRol = false;
        }
        return autentificarRol;
    }

    /**
     * Método qye verifica si un usuario tiene cierto permiso
     *
     * @param permiso
     * @return
     */
    public boolean hasPermisos(String permiso) {
        boolean autentificarPermiso;
        if (currentUser.isPermitted(permiso)) {
            log.info("El usuario [" +currentUser.getPrincipal()+"] ha podido "+ permiso);
            autentificarPermiso = true;
        } else {
            log.info("El usuario [" +currentUser.getPrincipal()+"] NO puede "+ permiso);
            autentificarPermiso = false;
        }
        return autentificarPermiso;
    }

}
