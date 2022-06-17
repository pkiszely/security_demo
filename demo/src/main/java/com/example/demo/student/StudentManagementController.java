package com.example.demo.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Folden"),
            new Student(2, "Maria Jones"),
            new Student(3, "John Kovacs")
    );


    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")             // preauthorized to access calling the api endpoint this does the same as antMatchers(HttpMethod.GET,"management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
    public List<Student> getAllStudents() {
        System.out.println("getAllStudents");
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")                      // same as in config -- .antMatchers(HttpMethod.POST,"management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
    public void registerNewStudent(@RequestBody Student student){
        System.out.println("Register new student");
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void delete(@PathVariable("studentId") Integer studentId){           // same as in config -- .antMatchers(HttpMethod.DELETE,"management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
        System.out.println("Delete student");
        System.out.println(studentId);
    }

    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student){
        System.out.println("Update student");
        System.out.println(String.format("%s %s", studentId, student));
    }
}
