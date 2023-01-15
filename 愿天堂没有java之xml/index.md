# 愿天堂没有Java之XML


**JavaSE 笔记（完）**

<!--more-->

> Java 是一门非常严谨的语言

#### 解析技术

##### 认识一下嘛

- XML 主要用于存储数据、做配置信息、进行数据传输
- 主要有两种解析方式：SAX 解析、DOM 解析

##### 常见解析工具

| 名称    | 说明                                                         |
| ------- | ------------------------------------------------------------ |
| `JAXP`  | SUN公司提供的一套XML的解析的API                              |
| `JDOM`  | JDOM是一个开源项目，它基于树型结构，利用纯JAVA的技术对XML文档实现解析、生成、序列化以及多种操作。 |
| `dom4j` | 是JDOM的升级品，用来读写XML文件的。具有性能优异、功能强大和极其易使用的特点，它的性能超过sun公司官方的dom  技术，同时它也是一个开放源代码的软件，Hibernate也用它来读写配置文件。 |
| `jsoup` | 功能强大DOM方式的XML解析开发包，尤其对HTML解析更加方便       |

##### 文档对象模型

- Document 对象：整个 XML 文档
- Node 对象：
  - Element 对象：标签
  - Attribute 对象：属性
  - Text 对象：文本内容

##### Dom4j 解析框架

- SAXReader 类

  | 构造器/方法                 | 说明                        |
  | --------------------------- | --------------------------- |
  | `public SAXReader()`        | 创建Dom4J的解析器对象       |
  | `Document read(String url)` | 加载XML文件成为Document对象 |

- Document 类

  | 方法名                     | 说明           |
  | -------------------------- | -------------- |
  | `Element getRootElement()` | 获得根元素对象 |

- 解析节点

  | 方法名                                 | 说明                                                         |
  | -------------------------------------- | ------------------------------------------------------------ |
  | `List<Element> elements()`             | 得到当前元素下所有子元素                                     |
  | `List<Element>  elements(String name)` | 得到当前元素下指定名字的子元素返回集合                       |
  | `Element  element(String name)`        | 得到当前元素下指定名字的子元素,如果有很多名字相同的返回第一个 |
  | `String  getName()`                    | 得到元素名字                                                 |
  | `String attributeValue(String name)`   | 通过属性名直接得到属性值                                     |
  | `String  elementText(子元素名)`        | 得到指定名称的子元素的文本                                   |
  | `String  getText()`                    | 得到文本                                                     |

- 用例

  ```java
  public void test() throws Exception {
    // 1、导入框架
    // 2、创建SaxReader对象
    SAXReader saxReader = new SAXReader();
    // 3、加载XML文件成为文档对象Document对象。
    Document document = saxReader.read(Dom4JTest2.class.getResourceAsStream("/poria.xml"));
    // 4、先拿根元素
    Element root = document.getRootElement();
    // 5、提取contact子元素
    List<Element> contactEles = root.elements("contact");
    // 6、准备一个ArrayList集合封装联系人信息
    List<Contact> contacts = new ArrayList<>();
    // 7、遍历Contact子元素
    for (Element contactEle : contactEles) {
      // 8、每个子元素都是一个联系人对象
      Contact contact = new Contact();
      // 因为解析出的值都是 String 类型，所以需要类型转换
      contact.setId(Integer.valueOf(contactEle.attributeValue("id")));
      contact.setVip(Boolean.valueOf(contactEle.attributeValue("vip")));
      contact.setName(contactEle.elementTextTrim("name"));
      contact.setGender(contactEle.elementTextTrim("gender").charAt(0));
      contact.setEmail(contactEle.elementText("email"));
      // 9、把联系人对象数据加入到List集合
      contacts.add(contact);
    }
    // 10、遍历List集合
    for (Contact contact : contacts) {
      System.out.println(contact);
    }
  }
  ```

#### 检索技术

##### 认识一下嘛

- XPath 在解析 XML 文档方面提供了一独树一帜的路径思想，更加优雅，高效
- XPath 使用路径表达式来定位 XML 文档中的元素节点或属性节点

##### 常用方法

| 方法名                             | 说明                     |
| ---------------------------------- | ------------------------ |
| `Node selectSingleNode("表达式")`  | 获取符合表达式的唯一元素 |
| `List<Node> selectNodes("表达式")` | 获取符合表达式的元素集合 |

##### 检索：绝对路径

- 采用绝对路径获取从根节点开始逐层的查找节点列表并打印信息

  | 方法名                  | 说明                                     |
  | ----------------------- | ---------------------------------------- |
  | `/根元素/子元素/孙元素` | 从根元素开始，一级一级向下查找，不能跨级 |

##### 检索：相对路径

- 先得到根节点

- 再采用相对路径获取下一级节点的子节点并打印信息

  | 方法名            | 说明                                       |
  | ----------------- | ------------------------------------------ |
  | `./子元素/孙元素` | 从当前元素开始，一级一级向下查找，不能跨级 |

##### 检索：全文搜索

- 直接全文搜索所有的元素并打印

  | 方法名             | 说明                                                     |
  | ------------------ | -------------------------------------------------------- |
  | `//元素`           | 找元素，无论元素在哪里                                   |
  | `//元素/子元素`    | 找元素，无论在哪一级，但子元素一定是元素的子节点         |
  | `//元素//子孙元素` | 元素无论在哪一种，子孙元素只要是元素的子孙元素都可以找到 |

##### 检索：属性查找

- 在全文中搜索属性，或者带属性的元素

  | 方法名                   | 说明                                                       |
  | ------------------------ | ---------------------------------------------------------- |
  | `//@属性名`              | 查找属性对象，无论是哪个元素，只要有这个属性即可。         |
  | `//元素[@属性名]`        | 查找元素对象，全文搜索指定元素名和属性名。                 |
  | `//元素//[@属性名="值"]` | 查找元素对象，全文搜索指定元素名和属性名，并且属性值相等。 |


---

> 作者: [晨星_茯苓](/about/)  
> URL: https://poriams.github.io/%E6%84%BF%E5%A4%A9%E5%A0%82%E6%B2%A1%E6%9C%89java%E4%B9%8Bxml/  

