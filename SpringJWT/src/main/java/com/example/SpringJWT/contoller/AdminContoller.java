package com.example.springjwt.contoller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminContoller {

    @GetMapping("/admin")
    public String adminP() {

        return "Admin Contoller";
    }
}
