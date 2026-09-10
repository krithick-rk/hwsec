package com.hwsec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.CommandLineRunner;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import jakarta.persistence.*;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@SpringBootApplication
@RestController
public class Application implements CommandLineRunner {
    @Autowired private EntityManager em;

    public static void main(String[] args) { SpringApplication.run(Application.class, args); }

    @Override
    @Transactional
    public void run(String... args) {
        em.createNativeQuery("CREATE TABLE product (id INT PRIMARY KEY, name VARCHAR(50), price DOUBLE)").executeUpdate();
        em.createNativeQuery("INSERT INTO product VALUES (1, 'Laptop', 999.0), (2, 'Mouse', 25.0)").executeUpdate();
    }

    @GetMapping("/api/products/search")
    @Transactional
    public List<?> searchProducts(@RequestParam String name) {
        String hql = "SELECT p.name FROM Product p WHERE p.name = :name";
        return em.createQuery(hql).setParameter("name", name).getResultList();
    }
}

@Entity
@Table(name = "product")
class Product {
    @Id private Integer id;
    private String name;
    private Double price;
    public Integer getId() { return id; }
    public String getName() { return name; }
    public Double getPrice() { return price; }
}
