# barry-gateway-service
基于Spring cloud gateway的网关  
|序号  |软件 | 版本   |  
| ------ | ------ |------ |  
|01|java | 1.8 |  
|02|spring | 5.1.3.RELEASE  |  
|03|spring boot | 2.1.1.RELEASE|  
|04|google guava | 15.0 |  
|05|spring cloud | Greenwich.SR2 |  
运行方式：  
编译方式：mvn clean install -DskipTests  

启动程序：java -jar barry-gateway-service.jar  
与注册中心进行结合，在配置文件中可以不配置对应的微服务请求路径  
在网关处对所有的请求参数进行XSS过滤，具体实现请查看： com.github.barry.xss.XssFilter
