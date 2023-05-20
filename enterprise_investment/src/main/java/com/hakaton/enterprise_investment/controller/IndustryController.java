package com.hakaton.enterprise_investment.controller;

import com.hakaton.enterprise_investment.dto.IndustryDto;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/industries")
public class IndustryController {


    @GetMapping
    public List<IndustryDto> getIndustries() {
        return List.of(
                new IndustryDto(1L, "Легкая промышленность"),
                new IndustryDto(2L, "Пищевая промышленность")
        );
    }
}
