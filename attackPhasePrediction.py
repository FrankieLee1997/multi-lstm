import Levenshtein
import pymysql


def getAttackChain():
    # 连接数据库,获取攻击序列
    conn = pymysql.connect(host="219.245.185.245", user="root", passwd="nsklab2018", database="mysql", charset='utf8')
    cur = conn.cursor()
    # 数据查询语句
    sql = "SELECT `chain` FROM attackChain WHERE effective=1;"
    cur.execute(sql)
    conn.commit()
    # 数据查询结果
    ret = cur.fetchall()
    cur.close()
    conn.close()
    return ret


def findMaxSimilarity(s, stmp):
    sSim = ''
    sMax = -1
    for ss in s:
        # 计算相似度
        sim = Levenshtein.seqratio(stmp, ss)
        # 数据库中相似度最高且包含当前攻击阶段的攻击序列
        if (sim > sMax) and (stmp[-1] in ss):
            sSim = ss
            sMax = sim
    return sSim


def attackPhasePrediction(stageNow, sSim):
    tmp = sSim.index(stageNow) #找出当前阶段所处位置
    rett = ""
    if tmp < (len(sSim) - 1):
         rett = sSim[tmp + 1]
    else:
        # 如果当前攻击阶段为攻击序列的最后阶段，则返回0
        rett = "0"
    return rett

if __name__ == '__main__':
    # 获取数据库中的攻击序列
    chains = getAttackChain()
    stmp = ['1', '3', '5']  # 待测序列
    stageNow = stmp[-1] # 当前攻击阶段
    print("当前攻击阶段：" + stageNow)
    # 序列解析
    s = []
    for str in chains:
        ss = []
        for stage in str[0].split('-'):
            ss.append(stage)
        s.append(ss)

    # 找出相似度最高的攻击序列
    sSim = findMaxSimilarity(s, stmp)
    print("相似度最高的攻击序列：")
    print(sSim)
    # 预测下一攻击阶段
    stageNext = attackPhasePrediction(stageNow, sSim)

    print("预测的下一攻击阶段：" + stageNext)



