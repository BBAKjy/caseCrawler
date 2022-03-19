import time
from selenium import webdriver
from selenium.webdriver import ActionChains
from webdriver_manager.chrome import ChromeDriverManager

url = input("URL(include scheme): ") # https://www.test.com/a/b/c

options = webdriver.ChromeOptions()
options.add_experimental_option("excludeSwitches", ["enable-logging"])

driver = webdriver.Chrome(ChromeDriverManager().install(), options = options) # need not download webdriver
driver.implicitly_wait(10)
driver.maximize_window()
driver.get(url)

time.sleep(1)

for l in range(1,469): # 469

    f = open('result.txt', 'a', encoding='UTF-8')

    res = []
    res.append(driver.find_element_by_xpath('/html/body/section/div/div[1]/div[3]/table/tbody/tr['+str(l)+']/td[1]').text + '\n') 
    driver.execute_script('window.scrollBy(0, 50)')

    time.sleep(1) # browser scroll delay

    try:
        driver.find_element_by_xpath('/html/body/section/div/div[1]/div[3]/table/tbody/tr['+str(l)+']/td[3]/button').click() # popup open

    except: # click function can't find the point exception
        driver.execute_script('window.scrollBy(0, 50)')
        driver.find_element_by_xpath('/html/body/section/div/div[1]/div[3]/table/tbody/tr['+str(l)+']/td[3]/button').click()
                                    
    for t in range(1, 19): # get cvss, description, date, ....
        res.append(driver.find_element_by_xpath('/html/body/section/div/div[1]/div[3]/div[2]/div/div[2]/div/p['+str(t)+']/span[2]').text + '\n')

    print(driver.find_element_by_xpath('/html/body/section/div/div[1]/div[3]/table/tbody/tr['+str(l)+']/td[1]').text) # print title

    driver.execute_script('closeModal()') # popup close

    time.sleep(1) # popup close delay

    res.append('\n')

    for w in res: # write loop result on file
        f.write(w)

    f.close()
