package com.nistruct.authorizationserver.dao;

import com.nistruct.authorizationserver.model.UserEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Repository
public class OAuthDAOServiceImpl implements OAuthDAOService {

    private final JdbcTemplate jdbcTemplate;

    public OAuthDAOServiceImpl(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    @Transactional
    public UserEntity getUserDetails(String emailId) {

        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        List<UserEntity> list = jdbcTemplate.query("SELECT * FROM USER WHERE EMAIL_ID=?", new String[]{emailId},
                (ResultSet rs, int rowNum) -> {
                    UserEntity user = new UserEntity();
                    user.setEmailId(emailId);
                    user.setId(rs.getString("ID"));
                    user.setName(rs.getString("NAME"));
                    user.setPassword(rs.getString("PASSWORD"));
                    return user;
                });

        if (!list.isEmpty()) {
            UserEntity userEntity = list.get(0);

            List<String> permissionList = jdbcTemplate.query("SELECT DISTINCT P.PERMISSION_NAME FROM PERMISSION P \r\n" +
                            "INNER JOIN ASSIGN_PERMISSION_TO_ROLE P_R ON P.ID = P_R.PERMISSION_ID\r\n" +
                            "INNER JOIN ROLE R ON R.ID = P_R.ROLE_ID \r\n" +
                            "INNER JOIN ASSIGN_USER_TO_ROLE U_R ON U_R.ROLE_ID=R.ID\r\n" +
                            "INNER JOIN USER U ON U.ID=U_R.USER_ID\r\n" +
                            "WHERE U.EMAIL_ID=?;", new String[]{userEntity.getEmailId()},
                    (ResultSet rs, int rowNum) -> {
                        return rs.getString("PERMISSION_NAME");
                    });

            List<String> role = jdbcTemplate.query("SELECT DISTINCT R.ROLE_NAME FROM ROLE R \n" +
                            "INNER JOIN ASSIGN_USER_TO_ROLE U_R ON U_R.ROLE_ID=R.ID\n" +
                            "INNER JOIN USER U ON U.ID=U_R.USER_ID\n" +
                            "WHERE U.EMAIL_ID=?;", new String[]{userEntity.getEmailId()},
                    (ResultSet rs, int rowNum) -> {
                        return "ROLE_" + rs.getString("ROLE_NAME");
                    });

            GrantedAuthority roleAuthority = new SimpleGrantedAuthority(role.get(0));
            grantedAuthorities.add(roleAuthority);

            if (permissionList != null && !permissionList.isEmpty()) {
                for (String permission : permissionList) {
                    GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(permission);
                    grantedAuthorities.add(grantedAuthority);
                }
            }
            list.get(0).setGrantedAuthorities(grantedAuthorities);

            return userEntity;
        }

        return null;
    }
}
