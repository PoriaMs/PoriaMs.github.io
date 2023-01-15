# 愿天堂没有Java之面向对象进阶


**JavaSE 笔记（二）**

<!--more-->

> Java 是一门非常严谨的语言

#### final

##### 认识一下嘛

- 可以修饰
  - 方法：表明该方法是最终方法，不能被重写
  - 变量：表示该变量第一次赋值后，不能再次被赋值(有且仅能被赋值一次)
  - 类：表明该类是最终类，不能被继承

##### 注意事项

- 修饰基本类型：变量存储的数据值不能发生改变
- 修饰引用类型：存储的地址值不能改变，但是**地址指向的对象内容可以改变**

#### 常量

##### 认识一下嘛

- 常量是使用了`public static final`修饰的成员变量，必须有初始化值，而且执行的过程中其值不能被改变
- 可以用于做系统的配置信息，方便程序的维护，同时也能提高可读性

##### 执行原理

- 在编译阶段会进行宏替换，把使用常量的地方全部替换成真实的字面量
- 这样做的好处是让使用常量的程序的执行性能与直接使用字面量是一样的

#### 枚举

##### 认识一下嘛

- 是 Java 中的一种特殊类型
- 是为了做信息的标志和信息的分类

##### 格式

```java
修饰符 enum 枚举名称{
  第一行都是罗列枚举类实例的名称
}

enum Season{
  SPRING , SUMMER , AUTUMN , WINTER;
}
```

##### 特征

- 枚举类都是继承了枚举类型：`java.lang.Enum`
- 枚举都是最终类，不可以被继承
- 构造器都是私有的，枚举对外不能创建对象

#### 抽象类

##### 认识一下嘛

- 如果一个类中的某个方法的具体实现不能确定，就可以申明成 abstract 修饰的**抽象方法（不能写方法体了）**，这个类必须用 abstract 修饰，被称为抽象类

##### 格式

```java
修饰符 abstract class 类名{
  修饰符 abstract 返回值类型 方法名称(形参列表);
}

public abstract class Animal{
  public abstract void run();
}
```

##### 注意事项

- 得到了抽象方法，失去了创建对象的能力（这波是有得有失）
- 抽象类可以理解成类的不完整设计图，是用来被子类继承的
- 一个类如果继承了抽象类，那么这个类必须重写完抽象类的全部抽象方法，否则这个类也必须定义成抽象类
- 不能用 abstract 修饰变量、代码块、构造器

#### 接口

##### 认识一下嘛

- 接口是一种规范
- 接口不能实例化
- 接口中的成员都是 public 修饰，不论你写不写，因为规范的目的是为了公开化

##### 格式

```java
public interface 接口名{
  // 常量
  // 抽象方法
}
```

##### 使用方法

- 接口是用来被类实现的，实现接口的类叫做实现类，实现类可以理解为“子类”

- 接口可以被类单独实现，也可以被多实现

  ```java
  修饰符 class 实现类 implements 接口1, 接口2, 接口3 , ... {
  }
  ```

##### 接口与接口的关系

- 多继承，一个接口可以同时继承多个接口
- 规范合并，整合多个接口为同一个接口，便于子类实现

#### 内部类概述

##### 认识一下嘛

- 内部类就是定义在一个类里面的类，里面的类可以理解为寄生，外面的类可以理解为宿主

  ```java
  public class People{
    // 内部类
    public class Heart{
    }
  }
  ```

##### 使用场景

- 当一个事物的内部还有一个部分需要一个完整的结构进行概述，而这个内部的完整的结构又只为外部事物提供服务，那么这个内部事物就可以选择用内部类来设计
- 内部类通常可以方便的访问外部成员，包括**私有的成员**

##### 作用

- 提供了更好的封装性，可以在封装性这个层面做到更多控制

#### 内部类之一：静态内部类（了解）

##### 认识一下嘛

- 有 static 修饰，属于外部类本身
- 和普通类使用完全一致

##### 格式

```java
public class Outer{
  // 静态成员内部类
  public static class Inner{
  }
}

外部类名.内部类名 对象名称 = new 外部类名.内部类构造器;
Outer.Inner in = new Outer.Inner();
```

##### 总结

- 譬如汽车类中的发动机类
- 可以直接访问外部类的静态成员，不能直接访问外部类的实例成员

#### 内部类之二：成员内部类（了解）

##### 认识一下嘛

- 无static修饰，属于外部类的对象
- JDK16之前，成员内部类中不能定义静态成员，JDK 16开始也可以定义静态成员了

##### 格式

```java
public class Outer{
  // 成员内部类
  public class Inner{
  }
}

外部类名.内部类名 对象名称 = new 外部类构造器.new 内部类构造器;
Outer.Inner in = new Outer().new Inner();
```

##### 总结

- 譬如人类中的心脏类
- 可以直接访问外部类的静态成员，可以通过实例方法直接访问外部类的实例成员

#### 内部类之三：局部内部类（了解）

##### 认识一下嘛

- 局部内部类放在方法、代码块、构造器等执行体中
- 局部内部类的类文件名为：`外部类$内部类.class`

#### 内部类之四：匿名内部类

##### 认识一下嘛

- 本质上是一个没有名字的局部内部类，定义在方法、代码块等
- 方便创建子类对象，其实质就是为了简化代码

##### 格式

```java
new 类||抽象类名||接口名(){
  重写方法;
}

Animal a = new Animal() {
  public void run() {
  }
};
a. run();
```

##### 总结

- 匿名内部类是没有名称的
- 会创建一个匿名内部类的对象
- 匿名内部类的对象就是当前`new`的那个类型的子类

##### 实例

- 案例一

  ```java
  /*游泳接口*/
  public interface Swimming {
    void swim();
  }
  
  /* 测试类*/
  public class JumppingDemo {
    public static void main(String[] args) {
      //需求：goSwimming方法
      JumppingDemo.goSwimming(new Swimming(){
        @Override
        public void swim(){
          System.out.println("Poria不会游泳~~~");
        }
      });
      // 以上代码还可简化为
      JumppingDemo.goSwimming(() -> System.out.println("Poria不会游泳~~~"));
    }
    
    // 定义一个方法让所有角色进来一起比赛
    public static void goSwimming(Swimming swimming) {
      swimming.swim();
    }
  }
  ```

- 案例二

  ```java
  //  为按钮绑定点击事件监听器
  btn.addActionListener(new ActionListener() {
    @Override
    public void actionPerformed(ActionEvent e) {
      System.out.println("登录一下~~");
    }
  });
  
  // 以上代码还可简化为
  btn.addActionListener(e -> System.out.println("登录一下~~"));
  ```


---

> 作者: [晨星_茯苓](/about/)  
> URL: https://poriams.github.io/%E6%84%BF%E5%A4%A9%E5%A0%82%E6%B2%A1%E6%9C%89java%E4%B9%8B%E9%9D%A2%E5%90%91%E5%AF%B9%E8%B1%A1%E8%BF%9B%E9%98%B6/  

