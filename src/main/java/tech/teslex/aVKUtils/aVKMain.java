package tech.teslex.aVKUtils;

import cn.nukkit.plugin.PluginBase;
import cn.nukkit.utils.Config;
import cn.nukkit.utils.ConfigSection;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import sun.net.www.http.HttpClient;

import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.InflaterInputStream;


public class aVKMain extends PluginBase {

    public static final String NEED_VALIDATION = "need_validation";

    private static final String CLIENT_ID     = "3697615"; // НЕ ТРОГАТЬ
    private static final String CLIENT_SECRET = "AlVXZFMUqyrnABp8ncuU"; // НЕ ТРОГАТЬ
    private static final String DEFAULT_URL   = "https://api.vk.com/method/"; // НЕ ТРОГАТЬ

    private Config config;

    private boolean _2fa = false;

    private String method,
                   token,
                   scope,
                   login,
                   password;

    private boolean confirm = false;

    @Override
    public void onEnable() {
        this.saveResource("config.yml");
        this.config = new Config(
                new File(this.getDataFolder() + "/config.yml"),
                Config.YAML
        );

        Map<String, ConfigSection> auth = (Map<String, ConfigSection>) this.config.get("auth");
        this.setScope(String.valueOf(auth.get("scope")));

        boolean error = false;
        if(String.valueOf(auth.get("auth")).equals("enable")) {
            this.method = String.valueOf(auth.get("method"));
            this.getLogger().notice("Авторизация включена");
            this.getLogger().notice("Выбранный метод авторизации: " + this.method);
            ConfigSection data = auth.get("data");
            switch(this.method) {
                case "token":
                        if(!String.valueOf(data.get("token")).isEmpty()) {
                            if(this.isTokenValid(String.valueOf(data.get("token"))))
                                this.getLogger().notice("Авторизаци прошла успешно");
                            else {
                                this.getLogger().warning("Неверный токен. Необходима замена или вход по логину/паролю");
                                error = true;
                            }
                        }
                        else {
                            this.getLogger().warning("Токен отсутствует");
                            error = true;
                        }
                    break;

                case "login":

                        if(!String.valueOf(data.get("login")).isEmpty()) {
                            String login    = String.valueOf(data.get("login"));
                            String password = String.valueOf(data.get("password"));
                            if(!login.isEmpty() || !password.isEmpty()) {
                                JsonObject response = this.authByPassword(login, password);
                                this.getLogger().info(String.valueOf(response));
                                if(response.get("error") == null) {
                                    data.put("token", String.valueOf(response.get("access_token")));
                                    auth.put("data", data);
                                    this.config.set("auth", auth);
                                    this.config.save();
                                    this.getLogger().notice("Авторизация прошла успешно. Токен сохранен в файле конфигураций");
                                }
                                else {
                                    if(String.valueOf(response.get("error")).equals(NEED_VALIDATION)) {
                                        this.authByPassword(login, password, true);
                                        this._2fa = true;
                                        this.getLogger().warning("Необходимо подтверждение входа");
                                        this.getLogger().warning(
                                                "На номер страницы (" +
                                                String.valueOf(response.get("phone_mask")) +
                                                ") отправлен код подтверждения");
                                        this.getLogger().warning("Подтверждение: /vk <код подтверждения>");
                                    }
                                    else {
                                        this.getLogger().warning("Ошибка авторизации");
                                        this.getLogger().warning("Ошибка: " + String.valueOf(response.get("error")));
                                    }
                                }
                            }
                            else {
                                error = true;
                                this.getLogger().warning("Отсутствует логин или пароль");
                            }
                        }
                        else
                            error = true;
                    break;
            }
        }
        else
            this.getLogger().notice("Авторизация выключена");

        if(error) {
            this.getLogger().warning("Выключение плагина");
            this.setEnabled(false);
        }

    }

    /**
     *
     * @return boolean
     */
    public Boolean authByToken() {
        Map<String, String> params = new HashMap<>();
        params.put("access_token", this.token);
        JsonObject response = request("users.get", params);
        if(response.get("error") == null)
            return false;
        return true;
    }

    /**
     *
     * @param token String
     * @return boolean
     */
    public Boolean authByToken(String token) {
        Map<String, String> params = new HashMap<>();
        params.put("access_token", token);
        JsonObject response = request("users.get", params);
        this.getLogger().info(String.valueOf(response));
        if(response.get("error") == null)
            return true;
        return false;
    }

    /**
     *
     * @param token String
     * @param write boolean
     * @return boolean
     */
    public boolean authByToken(String token, boolean write) {
        Map<String, String> params = new HashMap<>();
        params.put("access_token", token);
        JsonObject response = request("users.get", params);
        if(response.get("error") != null)
            return false;
        if(write)
            this.token = token;
        return true;
    }

    /**
     *
     * @param token String
     * @return boolean
     */
    public boolean isTokenValid(String token) {
        if(token == null || token.isEmpty())
            token = this.token;
        if(this.authByToken(token))
            return true;
        return false;
    }

    /**
     *
     * @return JsonObject
     */
    public JsonObject authByPassword() {
        String login = this.login;
        String password = this.password;
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("client_id", CLIENT_ID);
        params.put("client_secret", CLIENT_SECRET);
        params.put("scope", this.scope);
        params.put("username", login);
        params.put("password", password);
        return this.request("token", params, "https://oauth.vk.com/");
    }

    /**
     *
     * @param login String
     * @param password String
     * @return JsonObject
     */
    public JsonObject authByPassword(String login, String password) {
        if(login == null)
            login = this.login;
        if(password == null)
            password = this.password;
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("client_id", CLIENT_ID);
        params.put("client_secret", CLIENT_SECRET);
        params.put("scope", this.scope);
        params.put("username", login);
        params.put("password", password);
        return this.request("token", params, "https://oauth.vk.com/");
    }

    /**
     *
     * @param login String
     * @param password String
     * @param _2fa boolean
     * @return JsonObject
     */
    public JsonObject authByPassword(String login, String password, boolean _2fa) {
        if(login == null)
            login = this.login;
        if(password == null)
            password = this.password;
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("client_id", CLIENT_ID);
        params.put("client_secret", CLIENT_SECRET);
        params.put("scope", this.scope);
        params.put("username", login);
        params.put("password", password);
        if(_2fa) {
            params.put("2fa_supported", "1");
            params.put("force_sms", "1");
        }
        return this.request("token", params, "https://oauth.vk.com/");
    }

    /**
     *
     * @param login String
     * @param password String
     * @param code String
     * @return JsonObject
     */
    public JsonObject authByPassword(String login, String password, String code) {
        if(login == null)
            login = this.login;
        if(password == null)
            password = this.password;
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("client_id", CLIENT_ID);
        params.put("client_secret", CLIENT_SECRET);
        params.put("scope", this.scope);
        params.put("username", login);
        params.put("password", password);
        if(code != null || !code.isEmpty())
            params.put("code", code);
        return this.request("token", params, "https://oauth.vk.com/");
    }

    /**
     *
     * @param apiMethod String
     * @param params Map<String, String>
     * @return JsonObject
     */
    public JsonObject request(String apiMethod, Map<String, String> params)  {
        String url = DEFAULT_URL + apiMethod + "?" + this.httpBuildQuery(params);
        return this.query(url);
    }

    /**
     *
     * @param apiMethod String
     * @param params Map<String, String>
     * @param token boolean
     * @return JsonObject
     */
    public JsonObject request(String apiMethod, Map<String, String> params, boolean token)  {
        if(token)
            params.put("access_token", this.token);
        String url = DEFAULT_URL + apiMethod + "?" + this.httpBuildQuery(params);
        return this.query(url);
    }

    /**
     *
     * @param apiMethod String
     * @param params Map<String, String>
     * @param url String
     * @return JsonObject
     */
    public JsonObject request(String apiMethod, Map<String, String> params, String url)  {
        if(url.isEmpty())
            url = DEFAULT_URL;
        url += apiMethod + "?" + this.httpBuildQuery(params);
        return this.query(url);
    }

    /**
     *
     * @param apiMethod String
     * @param params Map<String, String>
     * @param token boolean
     * @param url String
     * @return JsonObject
     */
    public JsonObject request(String apiMethod, Map<String, String> params, boolean token, String url)  {
        if(url == null || url.isEmpty())
            url = DEFAULT_URL;
        if(token)
            params.put("access_token", this.token);
        url += apiMethod + "?" + this.httpBuildQuery(params);
        return this.query(url);
    }

    private JsonObject query(String url) {
        try {
            URL res = new URL(url);
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(res.openStream())
            );
            String response = reader.readLine();
            reader.close();
            return this.parseJson(response);
        } catch(IOException e) {
            this.getLogger().critical(e.getMessage());
        }
        return new JsonObject();
    }

    /**
     *
     * @param str String
     * @return JsonObject
     */
    public JsonObject parseJson(String str) {
        return (JsonObject) new JsonParser().parse(str);
    }

    /**
     *
     * @param element JsonElement
     * @return JsonObject
     */
    public JsonObject parseJson(JsonElement element) {
        return (JsonObject) new JsonParser().parse(element.toString());
    }

    /**
     *
     * @param params Map<String, String>
     * @return String
     */
    private String httpBuildQuery(Map<String, String> params) {
        String query = "";
        for(Map.Entry<String, String> entry: params.entrySet())
            query += entry.getKey() + "=" + entry.getValue() + "&";
        return query;
    }

    private void setScope(String scopeString) {
        this.scope = scopeString;
    }

    /**
     *
     * @return String
     */
    public String getScope() {
        return this.scope;
    }

}
