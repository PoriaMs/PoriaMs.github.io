# 愿天堂没有Java之集合


**JavaSE 笔记（四）**

<!--more-->

> Java 是一门非常严谨的语言

#### 泛型概述

##### 认识一下嘛

- 可以在编译阶段约束操作的数据类型
- 格式为：`<数据类型>`，只能支持引用数据类型
- 可以定义的地方
  - 泛型类：类后面定义
  - 泛型方法：方法申明上定义
  - 泛型接口：接口后面定义

##### 优势

- 统一数据类型，把出现泛型变量的地方全部替换为传输的真实数据类型
- 把运行时期可能出现的问题提到了编译期间，避免了强制类型转换可能出现的异常

##### 泛型类

- 格式

  ```java
  修饰符 class 类名<泛型变量>{}
  
  public class MyArrayList<E> {
      private ArrayList lists = new ArrayList();
  
      public void add(E e){
          lists.add(e);
      }
  
      public void remove(E e){
          lists.remove(e);
      }
  
      @Override
      public String toString() {
          return lists.toString();
      }
  }
  ```

- 作用：编译阶段约定操作的数据的类型，类似于集合的作用

##### 泛型方法

- 格式

  ```java
  修饰符 <泛型变量> 方法返回值 方法名称(形参列表){}
  
  public static <T> void printArray(T[] arr){
    if(arr == null){
      return System.out.println(arr);
    }
    StringBuilder sb = new StringBuilder("[");
    for(int i = 0; i < arr.length; i++){
      sb.append(arr[i]).append(i == arr.length - 1 ? "" : ",");
    }
    sb.append("]");
    System.out.println(sb);
  }
  ```

- 作用：方法中可以使用泛型接收一切实际类型的参数，方法更具备通用性

##### 泛型接口

- 格式

  ```java
  修饰符 interface 接口名称<泛型变量>{}
  
  public interface Data<E> {
      void add(E e);
      void delete(int id);
      void update(E e);
      E queryById(int id);
  }
  ```

- 作用：实现类可以在实现接口的时候传入自己操作的数据类型，这样重写的方法都将是针对于该类型的操作

##### 通配符与上下限

- 通配符`?`
  - 可以在**使用**泛型中代表一切类型
  - `E T K V`是在**定义**泛型的时候使用的
- 上下限
  - `? extends Car`：此时，`?`必须是 Car 或者其子类，泛型上限
  - `? super Car`：此时，`?`必须是 Car 或者其父类，泛型下限

#### 集合概述

##### 认识一下嘛

- 集合和数组都是容器，用来存放数据
- 数组可以存储基本数据类型和引用类型，集合**只能存储引用类型**
- 但是数组完成定义之后，类型确定，长度确定；但是集合启动之后，**类型长度都可以发生变化**，更像是气球

##### 体系特点

- 集合分为两类
  - `Collection`单列集合，每个元素只包含一个值
  - `Map`双列集合，每个元素包含两个值（键值对）

#### Collection 集合

##### 认识一下嘛

- List（接口） 系列集合
  - ArrayList（实现类）：有序、可重复、有索引
  - LinkedList（实现类）：有序、可重复、有索引
- Set（接口） 系列集合
  - HashSet（实现类）：无序、不重复、无索引
  - LinkedHashSet（实现类）：有序、不重复、无索引
  - TreeSet（实现类）：按照大小默认升序排列、不重复、无索引

##### 注意事项

- 集合支持泛型
- 集合与泛型不支持基本类型，只支持引用类型
- 集合中存储的元素都被认为是对象

##### 常用方法

- Collection 是单列集合的祖宗接口，它的功能全部单列集合都可以继承使用

  | 方法名称                               | 说明                             |
  | -------------------------------------- | -------------------------------- |
  | `public  boolean add(E e)`             | 把给定的对象添加到当前集合中     |
  | `public  void clear()`                 | 清空集合中所有的元素             |
  | `public  boolean remove(E e)`          | 把给定的对象在当前集合中删除     |
  | `public  boolean contains(Object obj)` | 判断当前集合中是否包含给定的对象 |
  | `public  boolean isEmpty()`            | 判断当前集合是否为空             |
  | `public  int size()`                   | 返回集合中元素的个数。           |
  | `public  Object[] toArray()`           | 把集合中的元素，存储到数组中     |

##### 集合的遍历方式

- 方式一：迭代器

  - 获取迭代器

    | 方法名称                  | 说明                                                        |
    | ------------------------- | ----------------------------------------------------------- |
    | `Iterator<E>  iterator()` | 返回集合中的迭代器对象，该迭代器对象默认指向当前集合的0索引 |

  - 常用方法

    | 方法名称            | 说明                                                         |
    | ------------------- | ------------------------------------------------------------ |
    | `boolean hasNext()` | 询问当前位置是否有元素存在，存在返回true ,不存在返回false    |
    | `E  next()`         | 获取当前位置的元素，并同时将迭代器对象移向下一个位置，注意防止取出越界。 |

  - 用例

    ```java
    Iterator<String> it = lists.iterator();
    while(it.hasNext()){
      String ele = it.next();
      System.out.println(ele);
    }
    ```

- 方式二：增强 for 循环

  - 既可以遍历集合也可以遍历数组

  - 在遍历删除时可能会出现并发修改异常

  - 用例

    ```java
    for(元素数据类型 变量名 : 数组或者Collection集合) {
             //在此处使用变量即可，该变量就是元素
    }
    
    Collection<String> list = new ArrayList<>();
    list.add("poria1");
    list.add("poria2");
    list.add("poria3");
    for(String ele : list) {
      System.out.println(ele);
    }
    ```

- 方式三：lambda 表达式

  - 方法

    | 方法名称                                            | 说明               |
    | --------------------------------------------------- | ------------------ |
    | `default void forEach(Consumer<? super T> action):` | 结合lambda遍历集合 |

  - 用例

    ```java
    Collection<String> list = new ArrayList<>();
    list.add("poria1");
    list.add("poria2");
    list.add("poria3");
    lists.forEach(new Consumer<String>(){
      @Override
      pubilc void accept(String s){
        System.out.println(s);
      }
    });
    
    // 以上代码可以简化为
    lists.forEach(s -> System.out.println(s));
    ```

##### List 系列集合

- 特有方法

  | 方法名称                         | 说明                                   |
  | -------------------------------- | -------------------------------------- |
  | `void add(int  index,E element)` | 在此集合中的指定位置插入指定的元素     |
  | `E remove(int  index)`           | 删除指定索引处的元素，返回被删除的元素 |
  | `E set(int index,E  element)`    | 修改指定索引处的元素，返回被修改的元素 |
  | `E get(int  index)`              | 返回指定索引处的元素                   |

- 遍历方式

  - 迭代器
  - 增强 for 循环
  - Lambda 表达式
  - for 循环（List 集合有索引）

- ArrayList

  - 基于数组实现，定位元素快，增删则需要移位，效率较低
  - 第一次创建集合并添加元素时，会默认创建一个长度为10的数组

- LinkedList

  - 基于双链表实现，首位操作快，查询慢

  - 特有功能

    | 方法名称                     | 说明                             |
    | ---------------------------- | -------------------------------- |
    | `public  void addFirst(E e)` | 在该列表开头插入指定的元素       |
    | `public  void addLast(E e)`  | 将指定的元素追加到此列表的末尾   |
    | `public  E getFirst()`       | 返回此列表中的第一个元素         |
    | `public  E getLast()`        | 返回此列表中的最后一个元素       |
    | `public  E removeFirst()`    | 从此列表中删除并返回第一个元素   |
    | `public  E removeLast()`     | 从此列表中删除并返回最后一个元素 |

##### Set 系列集合

- 常见方法
  - 功能与 Collection 的基本一致
- LinkedHashSet
  - 基于数组 + 双链表 + 红黑树实现
- TreeSet
  - 基于红黑树实现排序
  - 该集合一定要排序，可以将元素按照指定的规则排序

##### 使用场景总结

- 元素可重复，有索引，索引查询要快
  - ArrayList 基于数组
- 元素可重复，有索引，首位操作快
  - LinkedList 基于链表
- 增删改查快，元素不重复、无序、无索引
  - HashSet 基于哈希表
- 增删改查快、元素不重复、有序、无索引
  - LinkedHashSet 基于哈希表和双链表

#### 可变参数

##### 认识一下嘛

- 可变参数在形参中可以接收**多个数据**

- 格式

  ```java
  数据类型...参数名称
  
  sum(); // 1、不传参数
  sum(10); // 2、可以传输一个参数
  sum(10, 20, 30); // 3、可以传输多个参数
  sum(new int[]{10, 20, 30, 40, 50}); // 4、可以传输一个数组
  
  public static void sum(int...nums)
  ```

##### 作用

- 非常灵活，方便。可以不传输参数，可以传输1个或者多个，也可以传输一个数组
- 可变参数在内部本质上就是一个数组

##### 注意事项

- 一个形参列表中可变参数只能有一个
- 可变参数必须**放在形参列表最后面**

#### 集合工具类

##### 认识一下嘛

- `java.utils.Collections`：是集合工具类
- Collections 不属于集合，是用来操作集合的工具类

##### 常用方法

| 方法名称                                                     | 说明                         |
| ------------------------------------------------------------ | ---------------------------- |
| `public static <T> boolean  addAll(Collection<? super T> c, T... elements)` | 给集合对象批量添加元素       |
| `public static void shuffle(List<?> list)`                   | 打乱List集合元素的顺序       |
| `public static <T> void sort(List<T> list)`                  | 将集合中元素按照默认规则排序 |
| `public static <T> void sort(List<T> list，Comparator<? super T> c)` | 将集合中元素按照指定规则排序 |

#### Map 集合

##### 认识一下嘛

- 一种双列集合，每个元素包含两个数据
- 每个元素格式：`key=value`（键值对元素）
- 也被称为“键值对集合”
- `{key1=value1, key2=value2, key3=value3, ...}`

##### 特点

- 键占主导
- 键是无序，不重复，无索引的，值不做要求
- 当键重复时，后面的键对应的值会覆盖前面的键的值
- 键值对都可以为 null
- 实现类
  - HashMap：键是无序，不重复，无索引
  - LinkedHashMap：键是有序，不重复，无索引
  - TreeMap：键是排序，不重复，无索引

##### 常用功能

| 方法名称                              | 说明                                 |
| ------------------------------------- | ------------------------------------ |
| `V  put(K key,V value)`               | 添加元素                             |
| `V  remove(Object key)`               | 根据键删除键值对元素                 |
| `void  clear()`                       | 移除所有的键值对元素                 |
| `boolean containsKey(Object key)`     | 判断集合是否包含指定的键             |
| `boolean containsValue(Object value)` | 判断集合是否包含指定的值             |
| `boolean isEmpty()`                   | 判断集合是否为空                     |
| `int  size()`                         | 集合的长度，也就是集合中键值对的个数 |

##### 遍历方式

- 方式一：键找值

  - 先获取 Map 集合的全部键的 Set 集合

  - 遍历键的 Set 集合，然后通过键提取对应值

  - 用到的方法

    | 方法名称             | 说明             |
    | -------------------- | ---------------- |
    | `Set<K>  keySet()`   | 获取所有键的集合 |
    | `V  get(Object key)` | 根据键获取值     |

  - 用例

    ```java
    Map<String , Integer> maps = new HashMap<>();
    maps.put("Poria",100);
    maps.put("Pupi1",100);
    Set<String> keys = maps.keySet();
    for (String key : keys) {
      int value = maps.get(key);
      System.out.println(key + "===>" + value);
    }
    ```

- 方式二：键值对

  - 先把 Map 集合转化为 Set 集合，Set 集合中的每个元素都是键值对实体类型了

  - 遍历 Set 集合，然后提取键以及提取值

  - 用到的方法

    | 方法名称                         | 说明                     |
    | -------------------------------- | ------------------------ |
    | `Set<Map.Entry<K,V>> entrySet()` | 获取所有键值对对象的集合 |
    | `K getKey()`                     | 获得键                   |
    | `V getValue()`                   | 获取值                   |

  - 用例

    ```java
    Map<String , Integer> maps = new HashMap<>();
    maps.put("Poria",100);
    maps.put("Pupi1",100);
    Set<Map.Entry<String, Integer>> entries = maps.entrySet();
    for(Map.Entry<String, Integer> entry : entries){
      String key = entry.getKey();
      int value = entry.getValue();
      System.out.println(key + "====>" + value);
    }
    ```

- 方式三：Lambda 表达式

  - 用到的方法

    | 方法名称                                                     | 说明                  |
    | ------------------------------------------------------------ | --------------------- |
    | `default void forEach(BiConsumer<?  super  K,  ? super  V>  action)` | 结合lambda遍历Map集合 |

  - 用例

    ```java
    Map<String , Integer> maps = new HashMap<>();
    maps.put("Poria",100);
    maps.put("Pupi1",100);
    maps.forEach(new BiConsumer<String, Integer>() {
      @Override
      public void accept(String key, Integer value) {
        System.out.println(key + "--->" + value);
      }
    });
    
    // 以上代码可简化为
    maps.forEach((k, v) -> System.out.println(k + "--->" + v));
    ```

##### 实现类

- HashMap
  - 底层为哈希表结构
  - 依赖 hashCode 方法和 equals 方法保证键的唯一
- LinkedHashMap
  - 底层依然是哈希表，但是额外多了一个双链表的机制记录存储的顺序
- TreeMap
  - 默认排序，只对键排序，基于红黑树实现

#### 不可变集合

##### 认识一下嘛

- 如果某个数据不能被修改，就将它拷贝到不可变集合中
- 当集合对象被不可信的库调用时，不可变形式是安全的

##### 常用方法

- 在 List，Set，Map接口中都存在 of 方法，可以创建一个不可变的集合

  | 方法名称                                    | 说明                               |
  | ------------------------------------------- | ---------------------------------- |
  | `static  <E> List<E> of(E…elements)`        | 创建一个具有指定元素的List集合对象 |
  | `static  <E> Set<E> of(E…elements)`         | 创建一个具有指定元素的Set集合对象  |
  | `static <K  , V>  Map<K，V> of(E…elements)` | 创建一个具有指定元素的Map集合对象  |


---

> 作者: [晨星_茯苓](/about/)  
> URL: https://poriams.github.io/%E6%84%BF%E5%A4%A9%E5%A0%82%E6%B2%A1%E6%9C%89java%E4%B9%8B%E9%9B%86%E5%90%88/  

