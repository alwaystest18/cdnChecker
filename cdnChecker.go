package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Workiva/go-datastructures/queue"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/retryabledns"
)

var validResolversList []string //可用dns服务器列表
var noCdnDomains []string       //未使用cdn的域名列表
var useCdnDomains []string      //使用cdn的域名列表
var noCdnIps []string           //未使用cdn的ip列表
var domainsInfo []string        //所有域名+对应ip信息记录在此列表中
var wg sync.WaitGroup

// 将文件内容转为字符列表，主要用于域名列表、cdn cname列表与dns服务器
func FileContentToList(filePath string) []string {
	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("fail to open file: " + filePath)
		os.Exit(2)
	}

	fileContentStr := strings.ReplaceAll(string(fileContent), "\r\n", "\n")
	contentList := strings.Split(fileContentStr, "\n")
	var newList []string
	for _, element := range contentList {
		if element != "" {
			newList = append(newList, element)
		}
	}
	return newList
}

// 判断字符串在数组元素中是否包含
func In(target string, str_array []string) bool {
	sort.Strings(str_array)
	index := sort.SearchStrings(str_array, target)
	if index < len(str_array) && str_array[index] == target {
		return true
	}
	return false
}

// 通过解析特定域名获取ip地址来找出提供列表中可用dns服务器
func FilterValidResolver(resolver string) {
	defer wg.Done()
	retries := 1
	tempResolverList := []string{resolver}
	dnsClient, _ := retryabledns.New(tempResolverList, retries)
	dnsResponses, _ := dnsClient.Query("public1.114dns.com", dns.TypeA)
	if In("114.114.114.114", dnsResponses.A) {
		validResolversList = append(validResolversList, resolver)
	}
}

// 判断域名的cname是否包含cdn cname，如果包含则判定使用了cdn
func InCdnCnameList(domainCnameList []string, cdnCnameList []string) bool {
	inCdnCname := false
	for _, domainCname := range domainCnameList {
		for _, cdnCname := range cdnCnameList {
			if strings.Contains(domainCname, cdnCname) {
				inCdnCname = true
				return inCdnCname
			}
		}
	}
	return inCdnCname
}

// 获取域名在特定dns上的解析ip，并且以.分割ip，取ip的前三部分，即解析ip为1.1.1.1,最终输出为[1.1.1],便于判断多个ip是否在相同网段
func ResolvDomainIpPart(domain string, resolver string) ([]string, error) {
	var domainIpsPart []string
	retries := 1
	resolverList := []string{resolver}
	dnsClient, err := retryabledns.New(resolverList, retries)
	if err != nil {
		return domainIpsPart, err
	}
	dnsResponses, err := dnsClient.Query(domain, dns.TypeA)
	if err != nil {
		return domainIpsPart, err
	} else if In(resolver, dnsResponses.A) { //如果dns的ip出现在查询结果中，判为误报，忽略结果
		return domainIpsPart, nil
	}
	ipsList := dnsResponses.A //[1.1.1.1, 2.2.2.2, 3.3.3.3]
	if len(ipsList) > 0 {
		for _, ip := range ipsList {
			ipParts := strings.Split(ip, ".")
			ipSplit := ipParts[0] + "." + ipParts[1] + "." + ipParts[2]
			domainIpsPart = UniqueStrList(append(domainIpsPart, ipSplit))
		}
	}
	return domainIpsPart, nil
}

// 字符型列表去重去空
func UniqueStrList(strList []string) []string {
	uniqList := make([]string, 0)
	tempMap := make(map[string]bool, len(strList))
	for _, v := range strList {
		if tempMap[v] == false && len(v) > 0 {
			tempMap[v] = true
			uniqList = append(uniqList, v)
		}
	}
	return uniqList
}

// 生成count个[start,end)结束的不重复的随机数
func GenerateRandomNumber(start int, end int, count int) []int {
	//范围检查
	if end < start || (end-start) < count {
		return nil
	}

	//存放结果的slice
	nums := make([]int, 0)
	//随机数生成器，加入时间戳保证每次生成的随机数不一样
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for len(nums) < count {
		//生成随机数
		num := r.Intn((end - start)) + start

		//查重
		exist := false
		for _, v := range nums {
			if v == num {
				exist = true
				break
			}
		}

		if !exist {
			nums = append(nums, num)
		}
	}

	return nums
}

// 判断域名是否使用cdn
func CdnCheck(domain string, cdnCnameList []string, resolversList []string, dnsxClient *dnsx.DNSX) {
	defer wg.Done()

	isCdn, _, _ := dnsxClient.CdnCheck(domain) //通过dnsx自带方法识别cdn，主要为根据ip范围判断国外主流cdn厂商
	dnsxResult, _ := dnsxClient.QueryOne(domain)
	domainCnameList := dnsxResult.CNAME
	tempDomainIpList := dnsxResult.A
	var domainIpList []string

	if len(tempDomainIpList) > 0 {
		for _, tempIp := range tempDomainIpList {
			if !In(tempIp, resolversList) {
				domainIpList = append(domainIpList, tempIp)
			}
		}
	} else {
		return
	}

	if isCdn {
		useCdnDomains = append(useCdnDomains, domain)
	}

	for _, domainIp := range domainIpList {
		domainsInfo = UniqueStrList(append(domainsInfo, domain+":"+domainIp))
	}

	if len(domainCnameList) == 0 && len(domainIpList) > 0 { //无cname但有A记录，直接判定未使用cdn
		noCdnDomains = append(noCdnDomains, domain)
		noCdnIps = UniqueStrList(append(noCdnIps, domainIpList...))
	} else if len(domainCnameList) > 0 && len(domainIpList) > 0 {
		if InCdnCnameList(domainCnameList, cdnCnameList) { //cdn在cdn cname列表中包含，直接判定使用cdn
			useCdnDomains = append(useCdnDomains, domain)
		} else {
			var domainIpPartList []string
			randNums := GenerateRandomNumber(0, len(resolversList), 30)
			for _, num := range randNums {
				resolver := resolversList[num]
				domainIpsWithResolver, err := ResolvDomainIpPart(domain, resolver)
				if err != nil {
					continue
				}
				domainIpPartList = UniqueStrList(append(domainIpPartList, domainIpsWithResolver...))
				if len(domainIpPartList) > 3 { //不同段ip数量达到4个就跳出循环，避免每个dns服务器都解析增加耗时
					break
				}
			}
			//不同段ip数量达到4个就判定为使用了cdn
			if len(domainIpPartList) > 3 {
				useCdnDomains = append(useCdnDomains, domain)
			} else {
				noCdnDomains = append(noCdnDomains, domain)
				noCdnIps = UniqueStrList(append(noCdnIps, domainIpList...))
			}
		}
	}
}

func main() {
	nowTime := time.Now().Format("200601021504")
	df := flag.String("df", "", "domain list file")
	cf := flag.String("cf", "cdn_cname", "cdn cname file")
	r := flag.String("r", "", "dns resolvers file")
	o := flag.String("o", "no_cdn_domains"+nowTime+".txt", "output domains that are not using cdn to file")
	oi := flag.String("oi", "no_cdn_ips"+nowTime+".txt", "output ips that are not using cdn to file")
	oc := flag.String("oc", "use_cdn_domains"+nowTime+".txt", "output domains that are using cdn to file")
	od := flag.String("od", "domain_info"+nowTime+".txt", "output domain info(domain:ip) to file")
	flag.Parse()

	noCdnDomainsFileName := *o
	noCdnIpsFileName := *oi
	useCdnDomainsFileName := *oc
	domainsInfoFileName := *od

	//get domains list
	domainsListFile := *df
	var domainsList []string
	domainsList = UniqueStrList(FileContentToList(domainsListFile))

	//get cdn cname list
	cdnCnameFile := *cf
	var cdnCnameList []string
	cdnCnameList = UniqueStrList(FileContentToList(cdnCnameFile))

	//get resolvers list
	resolversFile := *r
	tempResolversList := UniqueStrList(FileContentToList(resolversFile))

	queResolvers := queue.New(5) //dns服务器队列
	for _, resolver := range tempResolversList {
		queResolvers.Put(resolver)
	}
	for queResolvers.Len() > 0 {
		wg.Add(1)
		queResolverList, _ := queResolvers.Get(1)
		queResolver := queResolverList[0].(string)
		go FilterValidResolver(queResolver)
	}
	wg.Wait()
	if len(validResolversList) < 20 {
		fmt.Println("The number of valid resolvers is less than 20, May affect the accuracy of the results")
	}

	var DefaultOptions = dnsx.Options{
		BaseResolvers:     validResolversList,
		MaxRetries:        5,
		QuestionTypes:     []uint16{dns.TypeA},
		TraceMaxRecursion: math.MaxUint16,
		Hostsfile:         true,
	}
	//init dnsx client
	dnsxClient, _ := dnsx.New(DefaultOptions)

	que := queue.New(5) //域名队列

	for _, domain := range domainsList {
		que.Put(domain)
	}

	for que.Len() > 0 {
		wg.Add(1)
		queDomainList, _ := que.Get(1)
		queDomain := queDomainList[0].(string)

		go CdnCheck(queDomain, cdnCnameList, validResolversList, dnsxClient)
	}
	wg.Wait()

	//未使用cdn域名写入文件
	if len(noCdnDomains) > 0 {
		noCdnDomains = UniqueStrList(noCdnDomains)
		noCdnDomainsFile, _ := os.OpenFile(noCdnDomainsFileName, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0666)
		defer noCdnDomainsFile.Close()
		for _, noCdnDomain := range noCdnDomains {
			noCdnDomainsFile.WriteString(noCdnDomain + "\n")
		}
	}

	//未使用cdn的ip写入文件
	if len(noCdnIps) > 0 {
		noCdnIps = UniqueStrList(noCdnIps)
		noCdnIpsFile, _ := os.OpenFile(noCdnIpsFileName, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0666)
		defer noCdnIpsFile.Close()
		for _, noCdnIp := range noCdnIps {
			fmt.Println(noCdnIp)
			noCdnIpsFile.WriteString(noCdnIp + "\n")
		}
	}

	//使用cdn域名写入文件
	if len(useCdnDomains) > 0 {
		useCdnDomains = UniqueStrList(useCdnDomains)
		useCdnDomainsFile, _ := os.OpenFile(useCdnDomainsFileName, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0666)
		defer useCdnDomainsFile.Close()
		for _, useCdnDomain := range useCdnDomains {
			useCdnDomainsFile.WriteString(useCdnDomain + "\n")
		}
	}

	//域名+对应ip信息写入文件
	if len(domainsInfo) > 0 {
		domainsInfo = UniqueStrList(domainsInfo)
		domainsInfoFile, _ := os.OpenFile(domainsInfoFileName, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0666)
		defer domainsInfoFile.Close()
		for _, domainInfo := range domainsInfo {
			domainsInfoFile.WriteString(domainInfo + "\n")
		}
	}
}
