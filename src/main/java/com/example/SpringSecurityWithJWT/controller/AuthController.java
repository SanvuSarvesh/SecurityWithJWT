package com.example.SpringSecurityWithJWT.controller;

import com.example.SpringSecurityWithJWT.common.AuthenticationRequest;
import com.example.SpringSecurityWithJWT.common.AuthenticationResponse;
import com.example.SpringSecurityWithJWT.common.RegisterRequest;
import com.example.SpringSecurityWithJWT.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest registerRequest
    ) {
        AuthenticationResponse authResponse = authService.register(registerRequest);
        return  ResponseEntity.ok(authResponse);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        System.out.println("----------- -- -- > inside the controller");
        return ResponseEntity.ok(authService.authenticate(request));
    }

}
